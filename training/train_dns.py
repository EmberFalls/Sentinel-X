"""Train the DNS family from a prepared shared-feature Parquet table."""

from training.train_common import train_family


def train(input_path, output_dir):
    return train_family(input_path, output_dir, family="dns", schema_version="dns.v1")
