# CMake generated Testfile for 
# Source directory: /workspace/source/swift/swift-corelibs-libdispatch/tests
# Build directory: /workspace/source/swift/swift-corelibs-libdispatch/tests
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(dispatch_apply "/workspace/source/swift/swift-corelibs-libdispatch/tests/bsdtestharness" "/workspace/source/swift/swift-corelibs-libdispatch/tests/dispatch_apply")
set_tests_properties(dispatch_apply PROPERTIES  DEPENDS "bsdtestharness" ENVIRONMENT "NOLEAKS=1" TIMEOUT "120" WORKING_DIRECTORY "/workspace/source/swift/swift-corelibs-libdispatch/tests")
add_test(dispatch_api "/workspace/source/swift/swift-corelibs-libdispatch/tests/bsdtestharness" "/workspace/source/swift/swift-corelibs-libdispatch/tests/dispatch_api")
set_tests_properties(dispatch_api PROPERTIES  DEPENDS "bsdtestharness" ENVIRONMENT "NOLEAKS=1" TIMEOUT "120" WORKING_DIRECTORY "/workspace/source/swift/swift-corelibs-libdispatch/tests")
add_test(dispatch_debug "/workspace/source/swift/swift-corelibs-libdispatch/tests/bsdtestharness" "/workspace/source/swift/swift-corelibs-libdispatch/tests/dispatch_debug")
set_tests_properties(dispatch_debug PROPERTIES  DEPENDS "bsdtestharness" ENVIRONMENT "NOLEAKS=1" TIMEOUT "120" WORKING_DIRECTORY "/workspace/source/swift/swift-corelibs-libdispatch/tests")
add_test(dispatch_queue_finalizer "/workspace/source/swift/swift-corelibs-libdispatch/tests/bsdtestharness" "/workspace/source/swift/swift-corelibs-libdispatch/tests/dispatch_queue_finalizer")
set_tests_properties(dispatch_queue_finalizer PROPERTIES  DEPENDS "bsdtestharness" ENVIRONMENT "NOLEAKS=1" TIMEOUT "120" WORKING_DIRECTORY "/workspace/source/swift/swift-corelibs-libdispatch/tests")
add_test(dispatch_group "/workspace/source/swift/swift-corelibs-libdispatch/tests/bsdtestharness" "/workspace/source/swift/swift-corelibs-libdispatch/tests/dispatch_group")
set_tests_properties(dispatch_group PROPERTIES  DEPENDS "bsdtestharness" ENVIRONMENT "NOLEAKS=1" TIMEOUT "120" WORKING_DIRECTORY "/workspace/source/swift/swift-corelibs-libdispatch/tests")
add_test(dispatch_overcommit "/workspace/source/swift/swift-corelibs-libdispatch/tests/bsdtestharness" "/workspace/source/swift/swift-corelibs-libdispatch/tests/dispatch_overcommit")
set_tests_properties(dispatch_overcommit PROPERTIES  DEPENDS "bsdtestharness" ENVIRONMENT "NOLEAKS=1" TIMEOUT "120" WORKING_DIRECTORY "/workspace/source/swift/swift-corelibs-libdispatch/tests")
add_test(dispatch_context_for_key "/workspace/source/swift/swift-corelibs-libdispatch/tests/bsdtestharness" "/workspace/source/swift/swift-corelibs-libdispatch/tests/dispatch_context_for_key")
set_tests_properties(dispatch_context_for_key PROPERTIES  DEPENDS "bsdtestharness" ENVIRONMENT "NOLEAKS=1" TIMEOUT "120" WORKING_DIRECTORY "/workspace/source/swift/swift-corelibs-libdispatch/tests")
add_test(dispatch_after "/workspace/source/swift/swift-corelibs-libdispatch/tests/bsdtestharness" "/workspace/source/swift/swift-corelibs-libdispatch/tests/dispatch_after")
set_tests_properties(dispatch_after PROPERTIES  DEPENDS "bsdtestharness" ENVIRONMENT "NOLEAKS=1" TIMEOUT "120" WORKING_DIRECTORY "/workspace/source/swift/swift-corelibs-libdispatch/tests")
add_test(dispatch_timer "/workspace/source/swift/swift-corelibs-libdispatch/tests/bsdtestharness" "/workspace/source/swift/swift-corelibs-libdispatch/tests/dispatch_timer")
set_tests_properties(dispatch_timer PROPERTIES  DEPENDS "bsdtestharness" ENVIRONMENT "NOLEAKS=1" TIMEOUT "120" WORKING_DIRECTORY "/workspace/source/swift/swift-corelibs-libdispatch/tests")
add_test(dispatch_timer_short "/workspace/source/swift/swift-corelibs-libdispatch/tests/bsdtestharness" "/workspace/source/swift/swift-corelibs-libdispatch/tests/dispatch_timer_short")
set_tests_properties(dispatch_timer_short PROPERTIES  DEPENDS "bsdtestharness" ENVIRONMENT "NOLEAKS=1" TIMEOUT "120" WORKING_DIRECTORY "/workspace/source/swift/swift-corelibs-libdispatch/tests")
add_test(dispatch_timer_timeout "/workspace/source/swift/swift-corelibs-libdispatch/tests/bsdtestharness" "/workspace/source/swift/swift-corelibs-libdispatch/tests/dispatch_timer_timeout")
set_tests_properties(dispatch_timer_timeout PROPERTIES  DEPENDS "bsdtestharness" ENVIRONMENT "NOLEAKS=1" TIMEOUT "120" WORKING_DIRECTORY "/workspace/source/swift/swift-corelibs-libdispatch/tests")
add_test(dispatch_sema "/workspace/source/swift/swift-corelibs-libdispatch/tests/bsdtestharness" "/workspace/source/swift/swift-corelibs-libdispatch/tests/dispatch_sema")
set_tests_properties(dispatch_sema PROPERTIES  DEPENDS "bsdtestharness" ENVIRONMENT "NOLEAKS=1" TIMEOUT "120" WORKING_DIRECTORY "/workspace/source/swift/swift-corelibs-libdispatch/tests")
add_test(dispatch_timer_bit31 "/workspace/source/swift/swift-corelibs-libdispatch/tests/bsdtestharness" "/workspace/source/swift/swift-corelibs-libdispatch/tests/dispatch_timer_bit31")
set_tests_properties(dispatch_timer_bit31 PROPERTIES  DEPENDS "bsdtestharness" ENVIRONMENT "NOLEAKS=1" TIMEOUT "120" WORKING_DIRECTORY "/workspace/source/swift/swift-corelibs-libdispatch/tests")
add_test(dispatch_timer_bit63 "/workspace/source/swift/swift-corelibs-libdispatch/tests/bsdtestharness" "/workspace/source/swift/swift-corelibs-libdispatch/tests/dispatch_timer_bit63")
set_tests_properties(dispatch_timer_bit63 PROPERTIES  DEPENDS "bsdtestharness" ENVIRONMENT "NOLEAKS=1" TIMEOUT "120" WORKING_DIRECTORY "/workspace/source/swift/swift-corelibs-libdispatch/tests")
add_test(dispatch_timer_set_time "/workspace/source/swift/swift-corelibs-libdispatch/tests/bsdtestharness" "/workspace/source/swift/swift-corelibs-libdispatch/tests/dispatch_timer_set_time")
set_tests_properties(dispatch_timer_set_time PROPERTIES  DEPENDS "bsdtestharness" ENVIRONMENT "NOLEAKS=1" TIMEOUT "120" WORKING_DIRECTORY "/workspace/source/swift/swift-corelibs-libdispatch/tests")
add_test(dispatch_starfish "/workspace/source/swift/swift-corelibs-libdispatch/tests/bsdtestharness" "/workspace/source/swift/swift-corelibs-libdispatch/tests/dispatch_starfish")
set_tests_properties(dispatch_starfish PROPERTIES  DEPENDS "bsdtestharness" ENVIRONMENT "NOLEAKS=1" TIMEOUT "120" WORKING_DIRECTORY "/workspace/source/swift/swift-corelibs-libdispatch/tests")
add_test(dispatch_data "/workspace/source/swift/swift-corelibs-libdispatch/tests/bsdtestharness" "/workspace/source/swift/swift-corelibs-libdispatch/tests/dispatch_data")
set_tests_properties(dispatch_data PROPERTIES  DEPENDS "bsdtestharness" ENVIRONMENT "NOLEAKS=1" TIMEOUT "120" WORKING_DIRECTORY "/workspace/source/swift/swift-corelibs-libdispatch/tests")
add_test(dispatch_io_net "/workspace/source/swift/swift-corelibs-libdispatch/tests/bsdtestharness" "/workspace/source/swift/swift-corelibs-libdispatch/tests/dispatch_io_net")
set_tests_properties(dispatch_io_net PROPERTIES  DEPENDS "bsdtestharness" ENVIRONMENT "NOLEAKS=1" TIMEOUT "120" WORKING_DIRECTORY "/workspace/source/swift/swift-corelibs-libdispatch/tests")
add_test(dispatch_select "/workspace/source/swift/swift-corelibs-libdispatch/tests/bsdtestharness" "/workspace/source/swift/swift-corelibs-libdispatch/tests/dispatch_select")
set_tests_properties(dispatch_select PROPERTIES  DEPENDS "bsdtestharness" ENVIRONMENT "NOLEAKS=1" TIMEOUT "120" WORKING_DIRECTORY "/workspace/source/swift/swift-corelibs-libdispatch/tests")
add_test(dispatch_c99 "/workspace/source/swift/swift-corelibs-libdispatch/tests/bsdtestharness" "/workspace/source/swift/swift-corelibs-libdispatch/tests/dispatch_c99")
set_tests_properties(dispatch_c99 PROPERTIES  DEPENDS "bsdtestharness" ENVIRONMENT "NOLEAKS=1" TIMEOUT "120" WORKING_DIRECTORY "/workspace/source/swift/swift-corelibs-libdispatch/tests")
add_test(dispatch_plusplus "/workspace/source/swift/swift-corelibs-libdispatch/tests/bsdtestharness" "/workspace/source/swift/swift-corelibs-libdispatch/tests/dispatch_plusplus")
set_tests_properties(dispatch_plusplus PROPERTIES  DEPENDS "bsdtestharness" ENVIRONMENT "NOLEAKS=1" TIMEOUT "120" WORKING_DIRECTORY "/workspace/source/swift/swift-corelibs-libdispatch/tests")
