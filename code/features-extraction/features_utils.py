from tree_sitter import Language, Parser
from typing import Literal, Union
import logging
import csv
import datetime
import os
import math

"""
TODO:
* current situation: supports only JS
* what to improve: have to add a support to TS as well
"""
# Use the Language.build_library method to compile these into a library that's usable from Python. 
# This function will return immediately if the library has already been compiled since the last time its source code was modified
Language.build_library(
  # Store the library in the `build` directory
  'build/my-languages.so',

  # Include one or more languages
  [
    'vendor/tree-sitter-javascript'
  ]
)

# Load the languages into your app as Language objects:
JS_LANGUAGE = Language('build/my-languages.so', 'javascript')

# reate a Parser and configure it to use one of the languages:
parser = Parser()
parser.set_language(JS_LANGUAGE)

def parse_file(file_name):
    logging.debug(f"start func: parse_file")
    # Open the file using the open() function, specifying the mode as 'r' for reading.
    file = open(file_name, 'r')
    # Read the contents of the file using the read() method
    code = file.read()
    # Parse the file and get the syntax tree
    tree = parser.parse(bytes(code, 'utf-8'))
    root_node = tree.root_node
    return root_node

def search_keyword_in_package(root_node, keywords, sub_keywords) -> bool:
    """
    This function searches for a keyword or sub keyword in the code using a provided root node.
    
    Parameters:
        root_node (Node): The root node of the code tree.
        keywords (list of str): A list of keywords to search for.
        sub_keywords (dict of lists): A dictionary where the keys are the names of sub keywords, and the values are the lists of words that make up the sub keyword.
    
    Returns:
        bool: True if a keyword or sub keyword is found, False otherwise.
  
    TODO:
        * current situation: the function stops after the function finds the first match
        * what to improve: have to add the function the ability to count the number of occurrences of all keywords
    """
    logging.debug(f"start func: search_keyword_in_package")
    found = False
    
    for child in root_node.children:    
        # search if the child in one of the keywords
        logging.debug(f"child: {child.text.decode()}")
        if child.text.decode() in keywords:
            found = True
            logging.info(f"keyword found!\nThe keyword that was found is: {child.text.decode()}")
            break
        # search if the child in one of the sub keywords
        elif found == False:
            for inner_keyword in sub_keywords.values():
                # logging.debug(f"second loop, inner_keyword: {inner_keyword}")
                if child.text.decode() in inner_keyword[0]:
                    logging.info(f"sub keyword found!\nThe keyword that was found is: {child.text.decode()}")
                    inner_keyword[1].append(child.text.decode())
                    if inner_keyword[1] == inner_keyword[0]:
                        logging.info(f"The entire sub keyword was found!\n{inner_keyword[1]} == {inner_keyword[0]}")
                        found = True
                        break
        # recursion 
        if found == False:
            logging.debug("calling recursion")
            found = search_keyword_in_package(child, keywords, sub_keywords)
            if found:
                break
    
    logging.debug(f"results of search_keyword_in_code: {found}")
    return found

import os

def search_substring_in_package(directory_path: str, keywords: str) -> int:
    """
    This function searches for a keyword in the files within a directory.
    
    Parameters:
        directory_path (str): The path to the directory.
        keyword (list of str): A list of keywords to search for.
    
    Returns:
        int: 1 if the keyword is found in any of the files, 0 otherwise.
    """
    logging.debug(f"start func: search_substring_in_package")
    logging.info(f"directory_path: {directory_path}")
    for dirpath, dirnames, filenames in os.walk(directory_path):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            if filename.endswith(".js") or filename.endswith(".ts"):
                with open(file_path, "r") as file:
                    file_content = file.read()
                    for keyword in keywords:
                        if keyword in file_content:
                            return 1
    return 0

def bitwise_operation(list1, list2, operation) -> list:
    """
    Perform a bitwise operation between elements of two lists of 1s and 0s.

    Parameters:
    list1 (List[int]): The first list of elements (1 or 0).
    list2 (List[int]): The second list of elements (1 or 0).
    operation (str): The bitwise operation to perform, one of '&' (AND), '|' (OR), or '^' (XOR).

    Returns:
    List[int]: The result of the bitwise operation.

    Raises:
    ValueError: If the lists have different lengths or if the operation is not one of the supported operations.
    """
    logging.debug("start func: bitwise_operation")
    
    if len(list1) != len(list2):
        raise ValueError("Both lists must have the same length")
    if operation not in ['&', '|', '^']:
        raise ValueError("Invalid operation")

    operation_dict = {'&': '&', '|': '|', '^': '^'}
    operation = operation_dict[operation]
    result = [eval(f"{a} {operation} {b}") for a, b in zip(list1, list2)]
    
    return result

def general_search(root_node,keywords) -> Literal[1, 0]:
    logging.debug("start func: general_search")

     # Traverse the syntax tree and check for the specific line of code
    sub_keywords = {} # {index of the sublist in keywords: keyword, [words that found]}
    # for each sublist in keywords, add the index and the keyword
    for index, keyword in enumerate(keywords):
      if type(keyword) == list:
        sub_keywords[index] = [keyword, []]

    is_using = 0
    if search_keyword_in_package(root_node, keywords, sub_keywords):
        is_using = 1
    
    return is_using 

def extract_package_details(package_name: str) -> tuple:
    """
    Extracts the name and version of a package from its package name string.

    Parameters:
        package_name (str): The package name string in the format 'name' + '-v-' + 'version'.

    Returns:
        tuple: A tuple containing the name and version of the package as separate strings.

    Example:
        >>> extract_package_details('package-v-1.0')
        ('package', '1.0')
    """
    logging.debug("start func: extract_package_details")

    name, version = package_name.split('-v-')
    return (name, version)

def write_dict_to_csv(dict_data, csv_file, headers, method='w') -> None:
    """
    Writes the values of a dictionary to a CSV file.

    Parameters:
        dict_data (dict): The dictionary to be written to the CSV file.
        csv_file (str): The path to the CSV file.
        method (str, optional): The method to use when opening the CSV file.
            'w' for write (default), 'a' for append.
        headers (list): List of the headers 

    Returns:
        None
    """
    logging.debug("start func: write_dict_to_csv")

    with open(csv_file, method, newline='') as f:
        writer = csv.writer(f)
        if method == 'w':
            writer.writerow(headers)
        for values in dict_data.values():
            writer.writerow(values)

def write_each_package_and_version_to_csv_and_create_dir(package_features, main_dir, header):
    """
    Write the values of the 'package_features' dictionary to separate CSV files, such that every key value of each key 
    will be written to a different CSV file. The name of each CSV file will be 'change-features' and it will be stored in 
    the directories: 'name'/'version' (the directories will be created if they do not exist).
    Additionally, a CSV file named 'versions' will be written in the 'name' directory and will contain the version and 
    the date/time of the file creation.

    Parameters:
    - package_features (dict): a dictionary in the format: 
                            "{package_name:[name, version, feature1, feature2, ..., feature9, label ]}"
    - main_dir (str): the path to the main directory where the CSV files will be saved
    - headers (list): List of the headers 

    Returns: None
    """

    for package, values in package_features.items():
        name, version, *features, label = values

        dir_path = os.path.join(main_dir, name, version)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)

        file_path = os.path.join(dir_path, "change-features.csv")
        with open(file_path, 'w', newline='') as f:
            writer = csv.writer(f)
            for feature, value in zip(header, features):
                writer.writerow([feature, value])
        
        name_dir_path = os.path.join(main_dir, name)
        if not os.path.exists(name_dir_path):
            os.makedirs(name_dir_path)
        
        versions_file_path = os.path.join(name_dir_path, "versions.csv")
        with open(versions_file_path, "a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([version, datetime.datetime.now().isoformat()])
            
def calculate_entropy(data) -> Union[float, Literal[0]]:
    """
    Calculates the entropy of the input data.

    Parameters:
        data (bytes): binary data to calculate the entropy for.

    Returns:
        entropy (float): the entropy of the input data.
    """
    logging.debug("start func: calculate_entropy")

    entropy = 0
    # Iterate over all possible values of bytes (0 to 255)
    for x in range(256):
        # Calculate the probability of the byte value x appearing in the data
        p_x = float(data.count(x.to_bytes(1, "big")))/len(data)
        # If the probability is greater than 0, add to the entropy value
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
            
    # Return the entropy value
    return entropy

def find_longest_line_in_the_file(filename) -> int:
    """
    This function takes in a filename as an argument and returns the length of the longest line in the file.

    Parameters:
    filename (str): The name of the file to be read.

    Returns:
    int: The length of the longest line in the file.
    """
    logging.debug("start func: find_longest_line")
    
    with open(filename, 'r') as file:
        longest_line = 0
        for line in file:
            if len(line) > longest_line:
                longest_line = len(line)
                 
    return longest_line