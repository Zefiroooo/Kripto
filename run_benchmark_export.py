"""Run the 10-payload benchmark and export CSV + PNG charts into outputs/."""

from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt

from metrics import build_benchmark_figures, run_full_benchmark


def main() -> None:
    out_dir = Path(__file__).parent / "outputs"
    out_dir.mkdir(parents=True, exist_ok=True)

    def on_progress(done: int, total: int, message: str) -> None:
        print(f"[{done}/{total}] {message}")

    df = run_full_benchmark(n=3, progress_callback=on_progress)

    csv_path = out_dir / "benchmark_10_payload.csv"
    df.to_csv(csv_path, index=False)
    print(f"Saved CSV: {csv_path}")

    figs = build_benchmark_figures(df)
    for name, fig in figs.items():
        fig_path = out_dir / f"chart_{name}.png"
        fig.savefig(fig_path, dpi=200, bbox_inches="tight")
        plt.close(fig)
        print(f"Saved chart: {fig_path}")

    print("\nSummary:")
    print(
        df[
            [
                "Payload",
                "Hash Match",
                "BER (%)",
                "n-1 Blocked",
                "Entropi Ciphertext (bit/byte)",
                "Entropi Bit Share",
                "Korelasi Antar Share (Mean)",
                "Ekspansi (%)",
                "Enc (ms)",
                "Split (ms)",
                "Comb (ms)",
                "Dec (ms)",
                "Total (ms)",
            ]
        ].to_string(index=False)
    )


if __name__ == "__main__":
    main()
