mod benchmark_tools;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::time::Duration;

fn benchmark_bsgs(c: &mut Criterion) {
    c.bench_function("DLP 1_000", |b| {
        b.iter(|| benchmark_tools::get_time_dlp(black_box(1_000)))
    });

    let mut group_1_000_000 = c.benchmark_group("sample-size-example");
    group_1_000_000.significance_level(0.1).sample_size(60);
    group_1_000_000.measurement_time(Duration::new(30, 0));
    group_1_000_000.bench_function("DLP 1_000_000", |b| {
        b.iter(|| benchmark_tools::get_time_dlp(black_box(1_000_000)))
    });
    group_1_000_000.finish();

    let mut group_1_000_000_000 = c.benchmark_group("sample-size-example");
    group_1_000_000_000.significance_level(0.1).sample_size(10);
    group_1_000_000_000.measurement_time(Duration::new(600, 0));
    group_1_000_000_000.bench_function("DLP 1_000_000_000", |b| {
        b.iter(|| benchmark_tools::get_time_dlp(black_box(1_000_000_000)))
    });
    group_1_000_000_000.finish();

    let mut group_1_000_000_000_000 = c.benchmark_group("sample-size-example");
    group_1_000_000_000_000
        .significance_level(0.1)
        .sample_size(10);
    group_1_000_000_000_000.bench_function("DLP 1_000_000_000_000", |b| {
        b.iter(|| benchmark_tools::get_time_dlp(black_box(1_000_000_000_000)))
    });
    group_1_000_000_000_000.finish();
}

fn benchmark_kangaroo(_: &mut Criterion) -> eyre::Result<()> {
    benchmark_tools::gen()
}
criterion_group!(bsgs, benchmark_bsgs);
criterion_group!(kangaroo, benchmark_kangaroo);
criterion_main!(bsgs, kangaroo);
