"""Train the TLS/QUIC family from a prepared shared-feature Parquet table."""

from training.train_common import train_family


def train(input_path, output_dir):
    return train_family(input_path, output_dir, family="tls_quic", schema_version="tls_quic.v1")
