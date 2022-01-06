def main(argv):
  parser = optparse.OptionParser()
  build_utils.AddDepfileOption(parser)
  parser.add_option("--protoc", help="Path to protoc binary.")
  parser.add_option("--proto-path", help="Path to proto directory.")
  parser.add_option("--swift-out-dir",
      help="Path to output directory for swift files.")
  parser.add_option("--stamp", help="File to touch on success.")
  options, args = parser.parse_args(argv)

  build_utils.CheckOptions(options, parser, ['protoc', 'proto_path'])
  if not options.swift_out_dir: # and not options.srcjar:
    print '--swift-out-dir must be specified.'
    return 1

  with build_utils.TempDir() as temp_dir:
    out_arg = '--protoc_out=' + temp_dir

    # Check if all proto files (which are listed in the args) are opting to
    # use the lite runtime, otherwise we'd have to include the much heavier
    # regular proto runtime in Chrome.
    # TODO(jkrcal): Replace this check by '--java_lite_out=' for the out_arg
    # above once this works on the master branch of the protobuf library,
    # expected in version 4.0 (see https://crbug.com/800281).
    for proto_file in args:
      if not 'LITE_RUNTIME' in open(proto_file).read():
        raise Exception(
            'Mumba only supports lite protos. Please add "optimize_for = '
            'LITE_RUNTIME" to your proto file to enable the lite runtime.')
    # Generate swift files using protoc.
    build_utils.CheckOutput(
        [options.protoc, '--proto_path', options.proto_path, out_arg]
        + args)

    if options.swift_out_dir:
      build_utils.DeleteDirectory(options.swift_out_dir)
      shutil.copytree(temp_dir, options.swift_out_dir)
  
    if options.stamp:
      build_utils.Touch(options.stamp)

if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
