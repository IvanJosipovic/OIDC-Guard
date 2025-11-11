using BenchmarkDotNet.Running;

var _ = BenchmarkRunner.Run(typeof(Program).Assembly);
