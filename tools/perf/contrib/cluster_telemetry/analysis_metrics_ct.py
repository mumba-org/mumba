# Copyright 2018 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from core import perf_benchmark

from contrib.cluster_telemetry import ct_benchmarks_util
from contrib.cluster_telemetry import local_trace_measurement
from contrib.cluster_telemetry import page_set

from telemetry.web_perf import timeline_based_measurement


class AnalysisMetricsCT(perf_benchmark.PerfBenchmark):
  """Benchmark that reads in the provided local trace file and invokes TBMv2
     metrics on that trace"""

  test = local_trace_measurement.LocalTraceMeasurement
  metric_name = ""  # Set by ProcessCommandLineArgs.

  def CreateCoreTimelineBasedMeasurementOptions(self):
    tbm_options = timeline_based_measurement.Options()
    tbm_options.AddTimelineBasedMetric(AnalysisMetricsCT.metric_name)
    return tbm_options

  @classmethod
  def AddBenchmarkCommandLineArgs(cls, parser):
    super(AnalysisMetricsCT, cls).AddBenchmarkCommandLineArgs(parser)
    ct_benchmarks_util.AddBenchmarkCommandLineArgs(parser)
    parser.add_option('--metric-name', type='string',
                      default=None,
                      help='The metric to parse the trace with')

  @classmethod
  def ProcessCommandLineArgs(cls, parser, args):
    if not args.urls_list:
      parser.error('Please specify --urls-list')
    if not args.metric_name:
      parser.error('Please specify --metric-name')
    cls.metric_name = args.metric_name

  def CreateStorySet(self, options):
    return page_set.CTBrowserLessPageSet(options.urls_list)

  @classmethod
  def Name(cls):
    return 'analysis_metrics_ct'
