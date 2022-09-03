import logging

LOG = logging

LOG.basicConfig(
    level=LOG.DEBUG,
    filename="logs/logs.log",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
)
