# Copyright 2012 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# pylint: disable=bad-continuation,docstring-second-line-blank,redefined-builtin

"""Compile logic copied from upstream gyp.input module.

None of this is written by Chromium OS.  We have a copy here so people don't
have to install a copy of gyp itself in their system.

Last synced from:
https://chromium.googlesource.com/external/gyp/aca1e2c3d346d704adfa60944e6b4dd06f4728be
"""

import ast


class GypError(Exception):
  """Error class representing an error, which is to be presented
  to the user.  The main entry point will catch and display this.
  """


def CheckedEval(file_contents):
  """Return the eval of a gyp file.

  The gyp file is restricted to dictionaries and lists only, and
  repeated keys are not allowed.

  Note that this is slower than eval() is.
  """

  syntax_tree = ast.parse(file_contents)
  assert isinstance(syntax_tree, ast.Module)
  c1 = syntax_tree.body
  assert len(c1) == 1
  c2 = c1[0]
  assert isinstance(c2, ast.Expr)
  return CheckNode(c2.value, [])


def CheckNode(node, keypath):
  if isinstance(node, ast.Dict):
    dict = {}
    for key, value in zip(node.keys, node.values):
      assert isinstance(key, ast.Str)
      key = key.s
      if key in dict:
        raise GypError("Key '" + key + "' repeated at level " +
              repr(len(keypath) + 1) + " with key path '" +
              '.'.join(keypath) + "'")
      kp = list(keypath)  # Make a copy of the list for descending this node.
      kp.append(key)
      dict[key] = CheckNode(value, kp)
    return dict
  elif isinstance(node, ast.List):
    children = []
    for index, child in enumerate(node.elts):
      kp = list(keypath)  # Copy list.
      kp.append(repr(index))
      children.append(CheckNode(child, kp))
    return children
  elif isinstance(node, ast.Str):
    return node.s
  else:
    raise TypeError("Unknown AST node at key path '" + '.'.join(keypath) +
         "': " + repr(node))
