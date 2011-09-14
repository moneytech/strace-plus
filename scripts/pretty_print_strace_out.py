# Pretty-print the output of strace++, using gdb to print out the
# function/file/line info for stack traces
#
#   argv[1] - output from strace++ (use -o <outfile> option to create the trace file)
#
# (also requires the 'file' program to be installed in addition to 'gdb')
#
# by Philip Guo

import os, sys, re, subprocess, cPickle
from collections import defaultdict, namedtuple
from optparse import OptionParser


# Return a symbol table, which is a dict where:
#
#   Key: Filename
#   Value: Dict where ...
#            Key: hex address (string)
#            Value: (function name, instruction offset, filename, line number)
#                   Any of those fields might be null when there isn't adequate debug info
#
# containing all the debug info needed to pretty-print the entries from an
# strace++ output file.
#
# Input: fn is the filename of the strace++ output trace file
def create_symtab_for_strace_out(fn):
  # each element is a string representing a return address, e.g.,:
  #   '/lib32/libc-2.11.1.so:0x6990d:0xf769390d'
  # it's a colon-separated triple containing:
  #   1.) absolute path to the binary
  #   2.) our best guess at the offset within that binary
  #   3.) the original return address (in case the calculated offset is bogus)
  return_addrs_set = set()

  # do a first pass to find ALL return addresses, so that we can call gdb to do a lookup
  for line in open(fn):
    # look for a raw stack trace of addrs like:
    #   [ /lib32/libc-2.11.1.so:0x67aef:0xf75ccaef /lib32/libc-2.11.1.so:0x67e06:0xf75cce06 ]
    if line[0] == '[':
      first_rb = line.find(']')
      stack_addrs = line[1:first_rb].strip()
      if stack_addrs:
        stack_addrs = stack_addrs.split()
        for addr in stack_addrs:
          return_addrs_set.add(addr)


  # Key: filename
  # Value: set of (addr_offset, original_addr)
  d = defaultdict(set)

  for e in return_addrs_set:
    filename, addr_offset, original_addr = e.split(':')
    d[filename].add((addr_offset, original_addr))


  # Key: filename
  # Value: list of addresses to query (strings representing hex numbers)
  filenames_to_addrs = defaultdict(list)


  for filename, addrs_set in d.iteritems():
    # use the following heuristic to determine which address to use:
    #   - if the file is an 'executable', then use original_addr
    #   - otherwise if the file is a 'shared object', then use addr_offset
    #
    # shared objects are usually mmapped into "high" addresses and thus need an
    # addr_offset, while exectuables usually do NOT need an offset and can instead
    # use their original_addr to do symbol lookups
    (file_out, _) = subprocess.Popen(['file', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    if 'shared object' in file_out:
      for (addr_offset, _) in addrs_set:
        filenames_to_addrs[filename].append(addr_offset)
    elif 'executable' in file_out:
      for (_, original_addr) in addrs_set:
        filenames_to_addrs[filename].append(original_addr)
    else:
      print >> sys.stderr, "Warning:", filename, "doesn't appear to be an executable or shared library"


  return get_symbol_table_using_gdb(filenames_to_addrs)


# some fields might be null if there isn't adequate debug info
SymbolTableEntry = namedtuple('SymbolTableEntry',
                              ['func_name', 'instr_offset', 'src_filename', 'src_line_num'])

# Use gdb to probe the debug info of binaries in order to return a symbol
# table, which is structured as a dict where:
#
#   Key: Filename
#   Value: Dict where ...
#            Key: hex address (string)
#            Value: a SymbolTableEntry object
#
# The advantage of using gdb is that you can usually get file/line info, and gdb
# supports "splitdebug" binaries where the debug info is stored in a separate
# binary linked with .gnu_debuglink
# (See: http://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html)
#
# The disadvantage is that gdb is quite heavyweight.  Also, when you can't get
# .gnu_debuglink to work with custom paths (e.g., on Chrome OS), then gdb
# won't print out the proper debug info.  TODO: try to look into improving this!
#
# Input: filenames_to_addrs is a dict mapping each binary filename to a list of
# addresses (strings representing hex numbers) on which to query for debug info
def get_symbol_table_using_gdb(filenames_to_addrs):
  ret = defaultdict(dict)

  lineRE = re.compile('Line (\d+) of "(.*)" starts at address 0x\S+ <(.*?)> and ends at 0x\S+')
  # even if there's no line number info, it might give you the function name
  # e.g., in "No line number information available for address 0x857 <_dl_start_user>"
  # at least you can find out that the function name is _dl_start_user
  noLineInfoRE = re.compile('No line number information available for address 0x\S+ <(.*?)>')

  # for each file, create a gdb script to introspect all elements of addr_list
  for filename, addrs_lst in filenames_to_addrs.iteritems():
    # now create a gdb script with some filler and the critical line that makes
    # the query for debug info: 'info line *<addr>'
    tmp_gdb_script = open('temp.gdb', 'w')
    for addr in sorted(addrs_lst):
      print >> tmp_gdb_script, 'echo ===\\n'
      print >> tmp_gdb_script, 'echo ' + addr + '\\n'
      print >> tmp_gdb_script, 'info line *' + addr
    tmp_gdb_script.close() # force write to disk, or else temp.gdb will be empty!

    # now run:
    #   gdb <filename> -batch -x temp.gdb
    # and harvest its stdout
    # ( -batch mode allows gdb to produce 'clean' output and be run as a subprocess
    #   see: http://ftp.gnu.org/old-gnu/Manuals/gdb-5.1.1/html_node/gdb_8.html )
    (gdb_stdout, gdb_stderr) = subprocess.Popen(['gdb', filename, '-batch', '-x', 'temp.gdb'],
                                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    if gdb_stderr:
      print >> sys.stderr, "GDB warnings while processing %s:" % (filename,), gdb_stderr,

    # parse the output of gdb, where each record is:
    # ===
    # <hex address>
    # one or more lines containing the output of gdb (which should be appended together later)
    tokens = gdb_stdout.split('===')
    for t in tokens:
      if not t:
        continue
      # collapse all space-like characters into a single space to simplify parsing later
      t = re.sub('\s+', ' ', t).strip()
      hex_addr = t.split()[0].strip()
      # gdb output is the REST of the line
      gdb_out = t[len(hex_addr):].strip()
      #print hex_addr, gdb_out

      assert hex_addr.startswith('0x')

      m = lineRE.match(gdb_out)
      if m:
        (linenum, src_filename, funcname) = m.groups()
        # split up "funcname+offset", e.g., 'main+21'
        s = funcname.split('+')
        # don't just assume that funcname splits into either 1 or 2 components.  Sometimes
        # there are weird function names like "STRING::operator+=(char const*)+91"
        # containing a '+' in the function name!!!
        if len(s) > 1:
          offset = int(s[-1]) # the FINAL component should be the offset number
          funcname = '+'.join(s[:-1]) # join the REST of the components into funcname
        else:
          offset = 0
          funcname = s[0]

        ret[filename][hex_addr] = SymbolTableEntry(funcname, offset, src_filename, int(linenum))
      else:
        m = noLineInfoRE.match(gdb_out)
        if m:
          funcname = m.group(1)

          s = funcname.split('+')
          assert len(s) <= 2
          offset = 0
          if len(s) == 2:
            offset = int(s[1])
          funcname = s[0]
          ret[filename][hex_addr] = SymbolTableEntry(funcname, offset, None, None)

  return ret


# TODO: as an alternative implementation, consider to ...
# Use "readelf -s" to probe the debug info of a binary in order to generate a symbol
# table, which is structured as a dict where:
#
#   Key: Filename
#   Value: Dict where ...
#            Key: address
#            Value: pretty-printed file/line/function info (best effort)
#
# The advantage of using readelf is that it's very lightweight and widely available,
# and it also seems to support reading debug info from Gentoo-style splitdebug binaries
# where the debug info is stored in a separate binary linked with .gnu_debuglink
#
# TODO: Ugh, readelf doesn't seem to always follow the .gnu_debuglink link, though!
# On gLucid, try:
#   readelf -s /lib32/ld-2.11.1.so
#   readelf -s /usr/lib/debug/lib32/ld-2.11.1.so
# they contain different info ... but gdb can easily find BOTH files and unify their info!


StackEntry = namedtuple('StackEntry',
                        ['func_name', 'instr_offset', 'src_filename', 'src_line_num',
                         'binary_filename', 'addr_offset', 'raw_addr'])

# Returns True iff two StackEntry objects are equal WITHOUT comparing raw_addr.
# Sometimes two call sites are equal even though they have different raw
# addresses in the binary!!!
# (as another optimization --- we only need to compare binary_filename and
# addr_offset, since the debug info are obtained from those fields using gdb)
def equals_modulo_raw_addr(x, y):
  return x.binary_filename == y.binary_filename and \
         x.addr_offset == y.addr_offset


# Creates an object from a line of strace++ output and a symbol table (symtab)
class StraceLogEntry:
  def __init__(self, line, symtab):
    self.original_line = line.strip()
    self.original_strace_string = None # raw output from basic strace
    self.syscall_name = None

    # list of stack entries, each of which is a StackEntry (namedtuple) entry
    self.backtrace = []

    if line[0] == '[':
      first_rb = line.find(']')
      rest = line[first_rb+1:].strip()
      self.original_strace_string = rest

      # self.original_strace_string might be something like:
      #   "mprotect(0x8049000, 4096, PROT_READ)    = 0"
      # so the syscall name is what comes before the parens
      #
      # Note that sometimes there's a PID that appears before the syscall name
      # (e.g., when you use 'strace -f'), so in those cases, strip off the PID
      #   "2383 mprotect(0x8049000, 4096, PROT_READ)    = 0"
      first_paren = self.original_strace_string.find('(')
      self.syscall_name = self.original_strace_string[:first_paren].strip()
      toks = self.syscall_name.split()
      if len(toks) == 2:
        try:
          _ = int(toks[0]) # check if this is an int!
          self.syscall_name = toks[1].strip()
        except ValueError:
          pass

      stack_addrs = line[1:first_rb].strip()
      if stack_addrs:
        stack_addrs_lst = stack_addrs.split()
        for addr in stack_addrs_lst:
          binary_filename, addr_offset, raw_addr = addr.split(':')
          symtab_for_file = symtab[binary_filename]
          # try both addr_offset and raw_addr to see if either one matches:
          if addr_offset in symtab_for_file:
            syms = symtab_for_file[addr_offset]
          elif raw_addr in symtab_for_file:
            syms = symtab_for_file[raw_addr]
          else:
            syms = SymbolTableEntry(None, None, None, None)

          assert len(syms) == 4
          t = StackEntry(syms.func_name, syms.instr_offset, syms.src_filename, syms.src_line_num,
                         binary_filename, addr_offset, raw_addr)
          self.backtrace.append(t)

  # return backtrace up to a certain depth
  def get_backtrace(self, depth):
    return self.backtrace[:depth]


# generator that lazily generates ONE system call log entry at a time as an
# StraceLogEntry object (thus conserving memory)
def gen_strace_out_entry(fn, symtab, gen_all_lines=False):
  for line in open(fn):
    ret = StraceLogEntry(line, symtab)
    # if can't even extract a syscall name, then there's no point in yielding
    # this line ... unless gen_all_lines is True
    if ret.syscall_name or gen_all_lines:
      yield ret


def pretty_print_strace_out(fn, symtab, depth):
  for log_entry in gen_strace_out_entry(fn, symtab, True): # generate ALL lines
    if log_entry.backtrace:
      print log_entry.original_strace_string
      for t in log_entry.get_backtrace(depth):
        if not t.func_name:
          print '  > [unknown function]', t.binary_filename
        elif t.src_filename and t.src_line_num:
          print '  >', "%s() %s:%d" % (t.func_name, t.src_filename, t.src_line_num)
        else:
          print '  > %s() [%s]' % (t.func_name, t.binary_filename)
    else:
      print log_entry.original_line


# A tree data structure representing a hierarchy of syscalls and stack traces
# TODO: should support roll-ups and other aggregations
class NestedProfileTree:
  def __init__(self):
    # Key: syscall name
    # Value: SyscallNode object
    self.syscalls = {}

  def insert(self, syscall_name, stack_entry_lst):
    if syscall_name not in self.syscalls:
      self.syscalls[syscall_name] = SyscallNode(syscall_name)
    n = self.syscalls[syscall_name]
    n.insert(stack_entry_lst)

  def printme(self):
    for k in sorted(self.syscalls.keys()):
      self.syscalls[k].printme(0)

  # roll the tree up to the given depth, collapsing all nodes beyond depth and
  # summarizing their contributions
  def rollup(self, depth):
    for k, v in self.syscalls.iteritems():
      v.rollup(depth)


class SyscallNode:
  def __init__(self, syscall_name):
    self.syscall_name = syscall_name
    # each element is a StackFrameNode object
    self.children = []


  def insert(self, stack_entry_lst):
    if not stack_entry_lst:
      return

    front = stack_entry_lst[0]

    matching_node = None
    for c in self.children:
      if equals_modulo_raw_addr(c.entry, front):
        matching_node = c
        break

    if not matching_node:
      new_node = StackFrameNode(front)
      self.children.append(new_node)
      matching_node = new_node

    rest = stack_entry_lst[1:]
    if rest:
      # keep processing the next unit
      matching_node.insert(stack_entry_lst[1:])
    else:
      # this is it!
      matching_node.terminal_count += 1


  def printme(self, indent):
    print ' ' * indent + '===', self.syscall_name, '==='

    # sort by counts:
    sorted_children = reversed(sorted(self.children, key=lambda e: e.get_cumulative_terminal_count()))
    for c in sorted_children:
      c.printme(indent + 1)
    print

  # roll this SyscallNode up to the given depth, collapsing all nodes beyond
  # depth and summarizing their contributions
  def rollup(self, depth):
    for c in self.children:
      c.maybe_rollup(depth-1)


class StackFrameNode:
  def __init__(self, se):
    assert type(se) is StackEntry
    self.entry = se

    # each element is a SyscallStackTreeNode object
    self.children = []
    # how many stack traces END at this frame?
    # e.g., after processing the following traces:
    # [a, b], [a, b, c], terminal_count is 0 for the 'a'
    # node, 1 for the 'b' node, and 1 for the 'c' node
    self.terminal_count = 0

  def insert(self, stack_entry_lst):
    # copy-and-paste from above
    front = stack_entry_lst[0]

    matching_node = None
    for c in self.children:
      if equals_modulo_raw_addr(c.entry, front):
        matching_node = c
        break

    if not matching_node:
      new_node = StackFrameNode(front)
      self.children.append(new_node)
      matching_node = new_node

    rest = stack_entry_lst[1:]
    if rest:
      # keep processing the next unit
      matching_node.insert(stack_entry_lst[1:])
    else:
      # this is it!
      matching_node.terminal_count += 1

  def maybe_rollup(self, i):
    # base case
    if i <= 0:
      self.collapse()
    # recursive case
    else:
      for c in self.children:
        c.maybe_rollup(i-1)

  # collapse all children nodes and update terminal_count
  def collapse(self):
    self.terminal_count = self.get_cumulative_terminal_count()
    self.children = []

  # return self.terminal_count + terminal_count of all of your children
  def get_cumulative_terminal_count(self):
    total = self.terminal_count
    for c in self.children:
      total += c.get_cumulative_terminal_count()
    return total


  def printme(self, indent):
    if self.entry.func_name:
      func_to_print = self.entry.func_name
      if func_to_print[-1] != ')':
        func_to_print += '()'

    # try our best to print out useful info
    if self.entry.src_filename:
      assert self.entry.func_name
      assert self.entry.src_line_num
      entry_str = '%s+%d (%s:%d)' % (func_to_print, self.entry.instr_offset, self.entry.src_filename, self.entry.src_line_num)
    elif self.entry.func_name:
      entry_str = '%s+%d (%s)' % (func_to_print, self.entry.instr_offset, self.entry.binary_filename)
    else:
      entry_str = '<???> (%s)' % (self.entry.binary_filename,)

    # if terminal_count > 0, then include it in the print-out
    count_str = ''
    if self.terminal_count:
      count_str = '[' + str(self.terminal_count) + ']'
    else:
      # use cumulative count for children, if you're not a terminal node
      count_str = str(self.get_cumulative_terminal_count()) + ' '

    count_str = count_str.rjust(7)

    print count_str + ' ' + ('  ' * indent) + entry_str

    # sort by decreasing order of cumulative terminal count
    sorted_children = reversed(sorted(self.children, key=lambda e: e.get_cumulative_terminal_count()))
    for c in sorted_children:
      c.printme(indent + 1)


def create_syscalls_tree(fn, symtab):
  t = NestedProfileTree()
  for log_entry in gen_strace_out_entry(fn, symtab):
    t.insert(log_entry.syscall_name, log_entry.backtrace)
  return t


def print_syscalls_tree(tree, depth):
  t.rollup(depth) # roll the tree up to the given depth
  t.printme()



if __name__ == "__main__":
  parser = OptionParser()
  parser.add_option('--depth', dest='depth', type='int', default=sys.maxint,
                    help="only consider stacks of up to depth D", metavar="D")

  parser.add_option('--trace', action="store_true", dest="trace",
                    help="print full trace")

  parser.add_option('--tree', action="store_true", dest="tree",
                    help="print tree of syscalls/stacks")

  parser.add_option('--tree-use-cache', action="store_true", dest="tree_with_cache",
                    help="print tree of syscalls/stacks, using a cache file for faster performance, profile_tree.pickle (beware of stale cache files, though!)")

  # add an option to ignore functions emanating from certain binary files (e.g., libc)

  (options, args) = parser.parse_args()
  strace_outfile = args[0]


  if options.trace:
    symtab = create_symtab_for_strace_out(strace_outfile)
    pretty_print_strace_out(strace_outfile, symtab, options.depth)
  elif options.tree or options.tree_with_cache:
    if options.tree_with_cache and os.path.exists('profile_tree.pickle'):
      t = cPickle.load(open('profile_tree.pickle'))
    else:
      # might be SLOW, so cache results if possible!
      symtab = create_symtab_for_strace_out(strace_outfile)
      t = create_syscalls_tree(strace_outfile, symtab)
      if options.tree_with_cache:
        cPickle.dump(t, open('profile_tree.pickle', 'w'))

    print_syscalls_tree(t, options.depth)
