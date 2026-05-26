use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use rustmate::{
    ingest::{PacketBatch, PacketSource, PcapFileSource},
    perf_harness::{
        PerfFixtureKind, PerfHarnessConfig, PerfInput, PerfSuiteReport, PerfWorkerPlannerConfig,
        compare_to_baseline, run_perf_suite,
    },
};
use tokio::runtime::Builder;

#[derive(Debug, Parser)]
#[command(
    name = "rustmate-load",
    about = "Run reproducible rustmate load and throughput scenarios"
)]
struct Args {
    /// Synthetic fixture to generate when --pcap is not set.
    #[arg(long, value_enum, default_value_t = FixtureArg::HttpRequests)]
    fixture: FixtureArg,

    /// Offline pcap file to load once into memory and replay for each run.
    #[arg(long)]
    pcap: Option<PathBuf>,

    /// Synthetic flow count.
    #[arg(long, default_value_t = 50_000)]
    flows: usize,

    /// Messages per flow for keep-alive and mixed synthetic fixtures.
    #[arg(long, default_value_t = 4)]
    messages_per_flow: usize,

    /// Worker counts to compare. Use 0 for available parallelism, adaptive for planner choice.
    #[arg(long, value_delimiter = ',', value_parser = parse_worker_spec, default_value = "1,0")]
    workers: Vec<WorkerSpec>,

    /// Measured runs per worker count.
    #[arg(long, default_value_t = 3)]
    runs: usize,

    /// Warmup runs per worker count.
    #[arg(long, default_value_t = 1)]
    warmups: usize,

    /// Include warmup runs in the saved report.
    #[arg(long)]
    include_warmups: bool,

    /// Packet batch size used by the pipeline.
    #[arg(long, default_value_t = 4096)]
    batch_size: usize,

    /// Bounded worker input queue depth.
    #[arg(long, default_value_t = 8192)]
    worker_queue_depth: usize,

    /// Bounded worker-to-output event queue depth.
    #[arg(long, default_value_t = 8192)]
    event_queue_depth: usize,

    /// Flow and stream tracking cap used during the run.
    #[arg(long, default_value_t = 1_048_576)]
    max_flows: usize,

    /// Global stream content memory cap in bytes.
    #[arg(long, default_value_t = 536_870_912)]
    stream_content_bytes: usize,

    /// Per-stream content memory cap in bytes.
    #[arg(long, default_value_t = 8_388_608)]
    stream_content_bytes_per_stream: usize,

    /// Maximum workers the adaptive planner may select. 0 means available parallelism.
    #[arg(long, default_value_t = 0)]
    adaptive_max_workers: usize,

    /// Adaptive planner minimum packet budget per selected worker.
    #[arg(long, default_value_t = 4096)]
    adaptive_min_packets_per_worker: usize,

    /// Adaptive planner minimum routed-flow budget per selected worker.
    #[arg(long, default_value_t = 8)]
    adaptive_min_flows_per_worker: usize,

    /// Adaptive planner maximum allowed packet skew, max/average.
    #[arg(long, default_value_t = 2.5)]
    adaptive_max_packet_skew: f64,

    /// Adaptive planner maximum allowed byte skew, max/average.
    #[arg(long, default_value_t = 3.0)]
    adaptive_max_byte_skew: f64,

    /// Compare current report to a previous JSON report.
    #[arg(long)]
    baseline: Option<PathBuf>,

    /// Maximum allowed packets/sec regression against --baseline.
    #[arg(long, default_value_t = 10.0)]
    max_regression_pct: f64,

    /// Return non-zero when --baseline detects a regression beyond threshold.
    #[arg(long)]
    fail_on_regression: bool,

    /// Optional report path. Without it, the full JSON report is printed.
    #[arg(long)]
    output: Option<PathBuf>,

    /// Output serialization format for --output or stdout.
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    output_format: OutputFormat,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FixtureArg {
    HttpRequests,
    OutOfOrderHttp,
    HttpKeepAlive,
    MixedServices,
}

impl From<FixtureArg> for PerfFixtureKind {
    fn from(value: FixtureArg) -> Self {
        match value {
            FixtureArg::HttpRequests => Self::HttpRequests,
            FixtureArg::OutOfOrderHttp => Self::OutOfOrderHttp,
            FixtureArg::HttpKeepAlive => Self::HttpKeepAlive,
            FixtureArg::MixedServices => Self::MixedServices,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Json,
    Jsonl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkerSpec {
    Count(usize),
    Adaptive,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let runtime = Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;

    let input = if let Some(path) = args.pcap.as_deref() {
        let packets = runtime.block_on(load_pcap_packets(path, args.batch_size))?;
        PerfInput::from_pcap(path.display().to_string(), packets)
    } else {
        PerfInput::synthetic(args.fixture.into(), args.flows, args.messages_per_flow)
    };

    let worker_planner = PerfWorkerPlannerConfig {
        max_workers: args.adaptive_max_workers,
        min_packets_per_worker: args.adaptive_min_packets_per_worker,
        min_flows_per_worker: args.adaptive_min_flows_per_worker,
        max_packet_skew: args.adaptive_max_packet_skew,
        max_byte_skew: args.adaptive_max_byte_skew,
    };
    let worker_plan = input.plan_workers(worker_planner);
    let worker_counts = expand_worker_specs(&args.workers, worker_plan.selected_workers);
    let config = PerfHarnessConfig {
        runs: args.runs,
        warmups: args.warmups,
        worker_counts,
        include_warmups: args.include_warmups,
        batch_size: args.batch_size,
        worker_queue_depth: args.worker_queue_depth,
        event_queue_depth: args.event_queue_depth,
        max_flows: args.max_flows,
        stream_content_bytes: args.stream_content_bytes,
        stream_content_bytes_per_stream: args.stream_content_bytes_per_stream,
        worker_planner,
    };

    eprintln!(
        "rustmate-load input={} packets={} bytes={}",
        input.name,
        input.packet_count(),
        input.byte_count()
    );
    eprintln!(
        "adaptive workers={} ({})",
        worker_plan.selected_workers, worker_plan.reason
    );
    let mut report = runtime.block_on(run_perf_suite(&input, &config))?;
    if let Some(path) = args.baseline.as_deref() {
        let baseline = read_report(path)?;
        let comparison = compare_to_baseline(&report, &baseline, args.max_regression_pct);
        print_comparison(&comparison);
        let failed = comparison.failed;
        report.comparison = Some(comparison);
        if failed && args.fail_on_regression {
            write_report(&report, args.output.as_deref(), args.output_format)?;
            anyhow::bail!(
                "performance regression exceeded {:.2}%",
                args.max_regression_pct
            );
        }
    }
    print_summary(&report);

    write_report(&report, args.output.as_deref(), args.output_format)?;

    Ok(())
}

fn parse_worker_spec(raw: &str) -> std::result::Result<WorkerSpec, String> {
    let value = raw.trim().to_ascii_lowercase();
    match value.as_str() {
        "adaptive" | "auto" | "planned" => Ok(WorkerSpec::Adaptive),
        _ => value
            .parse::<usize>()
            .map(WorkerSpec::Count)
            .map_err(|_| format!("invalid worker spec: {raw}")),
    }
}

fn expand_worker_specs(specs: &[WorkerSpec], adaptive_workers: usize) -> Vec<usize> {
    let mut workers = specs
        .iter()
        .map(|spec| match spec {
            WorkerSpec::Count(workers) => *workers,
            WorkerSpec::Adaptive => adaptive_workers,
        })
        .collect::<Vec<_>>();
    workers.sort_unstable();
    workers.dedup();
    workers
}

async fn load_pcap_packets(
    path: &std::path::Path,
    batch_size: usize,
) -> Result<Vec<rustmate::packet::RawPacket>> {
    let mut source = PcapFileSource::open(path.to_path_buf())
        .with_context(|| format!("failed to open pcap {}", path.display()))?;
    let mut batch = PacketBatch::with_capacity(batch_size.max(1));
    let mut packets = Vec::new();

    loop {
        let read = source.next_batch(&mut batch).await?;
        if read == 0 {
            break;
        }
        packets.extend(batch.drain());
    }

    Ok(packets)
}

fn serialize_report(report: &PerfSuiteReport, format: OutputFormat) -> Result<String> {
    match format {
        OutputFormat::Json => serde_json::to_string_pretty(report).context("failed to encode JSON"),
        OutputFormat::Jsonl => {
            let mut out = String::new();
            out.push_str(&serde_json::to_string(&report.summary)?);
            out.push('\n');
            for run in &report.runs {
                out.push_str(&serde_json::to_string(run)?);
                out.push('\n');
            }
            Ok(out)
        }
    }
}

fn read_report(path: &std::path::Path) -> Result<PerfSuiteReport> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read baseline {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))
}

fn write_report(
    report: &PerfSuiteReport,
    output: Option<&std::path::Path>,
    format: OutputFormat,
) -> Result<()> {
    let serialized = serialize_report(report, format)?;
    if let Some(path) = output {
        fs::write(path, serialized)
            .with_context(|| format!("failed to write report {}", path.display()))?;
        eprintln!("wrote {}", path.display());
    } else {
        println!("{serialized}");
    }
    Ok(())
}

fn print_summary(report: &PerfSuiteReport) {
    eprintln!("workers  runs  packets/s       MB/s      avg ms   pkt skew");
    for aggregate in &report.summary.aggregates {
        let skew = report
            .runs
            .iter()
            .find(|run| run.run.workers == aggregate.workers && !run.run.warmup)
            .map(|run| run.diagnostics.packet_skew.max_over_average)
            .unwrap_or(0.0);
        eprintln!(
            "{:>7} {:>5} {:>12} {:>10} {:>10} {:>10}",
            aggregate.workers,
            aggregate.runs,
            format_rate(aggregate.packets_per_sec_avg),
            format_rate(aggregate.mb_per_sec_avg),
            format_rate(aggregate.elapsed_ms_avg),
            format!("{skew:.2}x")
        );
    }
}

fn print_comparison(comparison: &rustmate::perf_harness::PerfBaselineComparison) {
    eprintln!(
        "baseline comparison metric={} max_regression={:.2}%",
        comparison.metric, comparison.max_regression_pct
    );
    for result in &comparison.results {
        let delta = result
            .delta_pct
            .map(|delta| format!("{delta:.2}%"))
            .unwrap_or_else(|| "n/a".to_owned());
        eprintln!(
            "workers {:>3}: {:?} current={} baseline={} delta={}",
            result.workers,
            result.status,
            result
                .current_value
                .map(format_rate)
                .unwrap_or_else(|| "n/a".to_owned()),
            result
                .baseline_value
                .map(format_rate)
                .unwrap_or_else(|| "n/a".to_owned()),
            delta
        );
    }
}

fn format_rate(value: f64) -> String {
    if value >= 1_000_000.0 {
        format!("{:.2}m", value / 1_000_000.0)
    } else if value >= 1_000.0 {
        format!("{:.2}k", value / 1_000.0)
    } else {
        format!("{value:.2}")
    }
}
