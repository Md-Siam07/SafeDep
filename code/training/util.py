from distutils.log import info
import os
import csv
import logging
from datetime import datetime

def parse_date(timestamp) -> datetime:
    """
    Convert a timestamp string to a datetime object.

    Args:
    timestamp (str): Timestamp string in the format "%Y-%m-%dT%H:%M:%S.%fZ".

    Returns:
    datetime: The datetime object representing the timestamp.
    """
    logging.debug("start func: parse_date")
    
    return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")

def version_date(versions, feature_dir):
    """
    Get the date of a specific version.

    Args:
    versions (dict): A dictionary where the keys are strings representing package directories
                     and the values are dictionaries with version strings as keys and dates as values.
    feature_dir (str): A string representing the path to a specific feature directory.

    Returns:
    datetime: The date of the specific version. Returns None if the version is not found.
    """
    logging.info("start func: version_date")
    logging.debug(f'versions: {versions}')
    logging.debug(f'feature_dir: {feature_dir}')
    
    # Extract the package directory and version directory from the feature_dir path
    package_dir = os.path.dirname(feature_dir)
    version_dir = os.path.basename(feature_dir)
    logging.debug(f'package_dir: {package_dir}')
    logging.debug(f'version_dir: {version_dir}')
                    
    # If the package directory is not in the versions dictionary, read the versions.csv file and store the data
    if package_dir not in versions:
        version_dates = {}
        path = os.path.join(package_dir, "versions.csv")
        logging.debug(f'path: {path}')
        with open(os.path.join(package_dir, "versions.csv"), "r", encoding='utf-8-sig') as versions_file:
            for row in csv.reader(versions_file):
                version, timestamp = row
                date = parse_date(timestamp)
                logging.debug(f'version: {version} | timestamp: {timestamp}')
                logging.debug(f'date: {date}')
                version_dates[version] = date
        versions[package_dir] = version_dates
        logging.debug(f'versions[package_dir]: {versions[package_dir]}')
        
    # Return the date for the specific version directory, or None if the version is not found
    return versions[package_dir][version_dir] if version_dir in versions[package_dir] else None
