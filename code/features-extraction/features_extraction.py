
from typing import Literal
from features_utils import bitwise_operation, general_search, parse_file, extract_package_details\
, write_dict_to_csv, write_each_package_and_version_to_csv_and_create_dir, calculate_entropy\
    , find_longest_line_in_the_file, search_substring_in_package
import logging
import math
import os

LOGֹ_FORMAT = "%(levelname)s, time: %(asctime)s , line: %(lineno)d- %(message)s "
# create and configure logger
logging.basicConfig(
    filename="features-extraction-logging.log", level=logging.INFO, filemode="w"
)
logger = logging.getLogger()

def search_PII(root_node) -> Literal[1, 0]:
    """
    (1) Access to personally-identifying information (PII): creditcard numbers, passwords, and cookies
    TODO:
    * current situation: have only two keywords
    * what to improve: have more keywords after the data exploration
    """
    logging.info("start func: search_PII")

    keywords = ['screenshot', ['keypress', 'POST'], 'creditcard', 'cookies', 'passwords', 'appData']
    return general_search(root_node, keywords)
    
def search_file_sys_access(root_node) -> Literal[1, 0]:
    """
    (2) Access to specific system resources:
    (a) File-system access: reading and writing files
    """
    
    '''#(2)a
    File-system access: reading and writing files
    #require('fs') is the File System Library that provides a simple
    and convenient way to interact with the file system on the computer.
    It provides functions for reading and writing files,
    creating and deleting directories, and more.'''

    keywords = ['read','write','file', 'require("fs")', 'os = require("os")', 'platform', 'hostname', 'system32']
    
    logging.info("start func: search_file_sys_access")

    return general_search(root_node, keywords)
    
def search_file_process_creation(root_node) -> Literal[1, 0]:
    """
    (2) Access to specific system resources:
    (b) Process creation: spawning new processes
    """

    '''
        #(2)b
    Process creation: spawning new processes
    #exec -> execute, used to run cmd commands on the device, including creation of new processes.
    #spawn -> The spawn keyword in JavaScript is used to start a new process in Node.js.
    It creates a new process and runs a specified command in that process.
    #fork -> The fork method in the child_process module in Node.js is used to create a new
    Node.js process that is a child of the current process. Unlike the spawn method,
    which creates a new process and runs a separate command, the fork method creates
    a new process that runs the same code as the parent process.
    #child_process -> The child_process module in Node.js is a module for creating and controlling
    child processes in a Node.js application. It provides a way to start new processes,
    run shell commands, and manage the communication between a Node.js process and its child processes.'''
    
    logging.info("start func: search_file_process_creation")
    keywords = ['exec', 'spawn', 'fork', 'thread', 'process', 'child_process']
    return general_search(root_node, keywords) 

def search_network_access(root_node) -> Literal[1, 0]:
    """
    (2) Access to specific system resources:
    (c)Network access: sending or receiving data
    """
    logging.info("start func: search_network_access_data")
    '''(2)c
    Network access: sending or receiving data
    #send -> we use send keyweord because when it comes to outward comminicaton, we expect to receive data,
    but it is very very unlikely that we will transfer data out from the device.
    thus we marked 'send' keyword'''
    

    keywords = ['send', 'export', 'upload' ,'post', 'XMLHttpRequest', 'submit', 'dns', 'nodemailer']
    return general_search(root_node, keywords)     

def search_cryptographic_functionality(root_node) -> Literal[1, 0]:
    """
    (3) Use of specific APIs 
    (a) Access to crypto functionality:
    """
    logging.info("start func: search_crypto_data")

    '''(3)(a) Cryptographic functionality
    mining: The process of finding a hash that meets certain criteria in a cryptocurrency network.'''
    keywords = ['crypto', 'mining', 'miner', 'cpu']
    
    return general_search(root_node, keywords)

def search_data_encoding(root_node) -> Literal[1, 0]:
    """
    (3) Use of specific APIs
    (b) encoded data: find encoded data in the script
    """
    logging.info("start func: search_encoded_data")

    '''(3)(b) Data encoding using encodeURIComponent etc.
    base64 -> common encoding method.
    encodeURIComponent -> common encoding function with utf-8.
    querystring -> This is a built-in Node.js library for working with query strings. 
    It provides methods for encoding and decoding query strings.
    qs: This is a popular library for encoding and decoding query strings in both the browser and Node.js. 
    It provides a more powerful set of features compared to the built-in querystring library.
    btoa and atob: These are global functions in JavaScript for base64 encoding and decoding respectively.
    Buffer: This is a built-in class in Node.js for working with binary data.
    You can use the .toString('base64') method to encode binary data as a base64 string.
    JSON.stringify: This is a built-in method in JavaScript for converting a JavaScript object to a JSON string. 
    JSON is a widely used format for encoding data structures and exchanging data between client and server.'''

    keywords = ['encodeURIComponent', 'querystring', 'qs', 'base64', 'btoa', 'atob', 'Buffer', 'JSON.stringify']
    
    return general_search(root_node, keywords)


def search_dynamic_code_generation(root_node) -> Literal[1, 0]:
    """
    (3) encoded data: find encoded data in the script
    (c) search_dynamic_code_generation: run external scripts within the script
    """
    logging.info("start func: search_dynamic_code_generation")


    '''(3)(c) Dynamic code generation using eval, Function, etc.
    #eval -> a function that is used to dynamically execute the code defined in the string code.
    # Function -> Function constructor: This allows you to dynamically create a new function
    and execute it. The Function constructor takes a string of code as its
    argument and returns a reference to a new function that can be executed.'''
    keywords = ['eval', 'Function']
    
    return general_search(root_node, keywords)

def search_package_installation(root_node) -> Literal[1, 0]:
    """
    (4) search_package_installation: unautherized external package installation
    """
    logging.info("start func: search_dynamic_code_generation")

    '''(4) Use of package installation scripts
    #In npm, pre-install and post-install are scripts that can
    be defined in the scripts section of the package.json file.
    These scripts are executed before and after the installation of packages, respectively.'''
    keywords = ['preinstall', 'postinstall', 'install', 'sudo']

    return general_search(root_node, keywords)

def search_minified_code(directory_path) -> Literal[1, 0]:
    """
    (5) Presence of minified code (to avoid detection) or binary files (such as binary executables)
    Extracts the is_minified feature from the files in the directory.

    Parameters:
        directory_path (str): the path to the directory to extract features from.

    Returns:
        is_minified (int): 1 if the code is minified, 0 otherwise.
    """ 
    logging.info("start func: search_minified_code")
    logging.debug(f'directory_path: {directory_path}')
    
    # Store the entropy values of each file in the directory
    entropy_values = []

    # Loop over all the files in the directory tree rooted at directory_path
    for dirpath, dirnames, filenames in os.walk(directory_path):
        for filename in filenames:
            logging.debug(f'filename: {filename}')
            if not filename.endswith(".js") and not filename.endswith(".ts"):
                logging.debug('ignore')
                continue
            
            # Construct the file path for each file
            file_path = os.path.join(dirpath, filename)
            # Read the contents of the file as binary data
            with open(file_path, "rb") as f:
                data = f.read()
            if len(data) > 0:
                # Calculate the entropy of the binary data
                entropy = calculate_entropy(data)
                logging.debug(f"entropy: {entropy}")
                # Append the entropy to the list of entropy values
                entropy_values.append(entropy)

    is_minified = 0

    # Calculate the average entropy and standard deviation of the entropy values
    if len(entropy_values) != 0:
        avg_entropy = sum(entropy_values) / len(entropy_values)
        std_dev_entropy = math.sqrt(sum((x - avg_entropy)**2 for x in entropy_values) / len(entropy_values))

        # Create a feature indicating whether the data is minified or not
        AVG_ENTROPY_THRESHOLD = 5
        STD_DEV_ENTROPY_THRESHOLD = 0.1
        if avg_entropy > AVG_ENTROPY_THRESHOLD and std_dev_entropy > STD_DEV_ENTROPY_THRESHOLD:
            is_minified = 1          
        logging.info(f'avg_entropy: {avg_entropy}')
        logging.info(f'std_dev_entropy: {std_dev_entropy}')
        logging.info(f'is_minified: {is_minified}')
        
    return is_minified

def search_packages_with_no_content(directory_path: str) -> Literal[1, 0]:
    """
    The function takes in a directory path as input and returns 1 if the directory does not contain any '.js' or '.ts' files, and 0 otherwise.
    
    Args:
    - directory_path (str): The path to the directory being checked.
    
    Returns:
    - int: Returns 1 if the directory does not contain any '.js' or '.ts' files and 0 otherwise.
    
    """
    logging.info("start func: extract_is_has_no_content")
        
    # Loop over all the files in the directory tree rooted at directory_path
    for dirpath, dirnames, filenames in os.walk(directory_path):
        for filename in filenames:
            if not filename.endswith(".js") and not filename.endswith(".ts"):
                continue
            else:
                return 0
        
    return 1

def search_geolocation(directory_path) -> Literal[1, 0]:
    """
    search_geolocation: unautherized acess to the location of the device 
    """
    logging.info("start func: search_location")

    # searching for an API that gets the location of the device base on its IP.   
    keywords = ['ipgeolocation']

    return search_substring_in_package(directory_path, keywords)

def longest_line_in_the_package(directory_path: str) -> int:
    """
    The function returns the longest line in the package.
    Malicious packages sometimes use obfuscation techniques, 
    that write the whole code in the file as one line.
    
    Args:
    - directory_path (str): The path to the directory being checked.
    
    Returns:
    - int: Returns the longest line in the package.
    """
    logging.info("start func: longest_line_in_the_package")

    # Store the longest line in the package
    longest_line_package = 0

    # Loop over all the files in the directory tree rooted at directory_path
    for dirpath, dirnames, filenames in os.walk(directory_path):
        for filename in filenames:
            logging.debug(f'filename: {filename}')
            if not filename.endswith(".js") and not filename.endswith(".ts"):
                logging.debug('ignore')
                continue
            
            # Construct the file path for each file
            file_path = os.path.join(dirpath, filename)
            # Read the contents of the file as binary data
            longest_line_file = find_longest_line_in_the_file(file_path)
            if longest_line_file > longest_line_package:
                longest_line_package = longest_line_file
        
    return longest_line_package

def num_of_files_in_the_package(directory_path: str) -> int:
    """
    The function returns the number of files in the package.
    Malicious packages often tend to contain a very small amount of files.
    
    Args:
    - directory_path (str): The path to the directory being checked.
    
    Returns:
    - int: Returns the of files in the package.
    """
    logging.info("start func: num_of_files_in_the_package")

    # Store the number of files in the package
    num_of_files = 0

    # Loop over all the files in the directory tree rooted at directory_path
    for _, _, filenames in os.walk(directory_path):
        num_of_files += len(filenames)
            
    return num_of_files

def does_contain_license(directory_path: str) -> int:
    """
    The function returns 1 if the package contain a license file and 0 otherwise.
    
    Args:
    - directory_path (str): The path to the directory being checked.
    
    Returns:
    - int: Returns 1 if the package contain a license file and 0 otherwise.
    """
    logging.info("start func: is_contain_license")

    # Loop over all the files in the directory tree rooted at directory_path
    for _, _, filenames in os.walk(directory_path):
        for filename in filenames:
            if filename == 'LICENSE':
                return 1
        
    return 0
         
def extract_features(root_dir: str, malicious: bool) -> None:
    """
    This function is used to traverse a given directory and extract features of each javascript file in it.
    The extracted features are saved in a dictionary named `package_features` 
    in the format of `{package_name: [feature_1, feature_2, ..., feature_n]}`.

    Args:
    - root_dir (str): The path of the root directory to traverse.
    - malicious (bool): Indicates whether the files in the directory are malicious or benign.

    Returns:
    None. The function saves the extracted features in a csv file.

    """
    logging.info("start func: extract_features")
    logging.info(f'malicious?: {malicious}')
    
    package_features = {} # {package_name:[f1, f2, ..., fn]}
    visited_packages = set() # the set will contain the packages name that were traversed 
    NUM_OF_FEATURES_INCLUDE = 17 # number of features include name, version and label
    print('extracting features')
    for dirname, _, files in os.walk(root_dir):
        print('2:',dirname)
        path_lst = dirname.split(os.path.sep)
        packages_type = "malicious" if malicious else "benign"
        print('package-type:',packages_type)
        print('path-lst:',path_lst)
        package_index = path_lst.index(packages_type) + 1
        print('package_index:',package_index)
        for filename in files:
            if not filename.endswith(".js") and not filename.endswith(".json"):
                continue
            file_path = os.path.join(dirname, filename)
            package_name = path_lst[package_index]

            logging.debug('================================================')
            logging.debug(f"File path: {file_path}")
            logging.debug(f"Package name: {package_name}")
            logging.debug(f"filename: {filename}")
            
            # check if the current package name already exists in the package_features dictionary
            if package_name not in package_features:
                # if not, initialize a list of NUM_OF_FEATURES_INCLUDE elements with value 0
                init_lst = [0] * NUM_OF_FEATURES_INCLUDE
                package_features[package_name] = init_lst
            
            name, version = extract_package_details(package_name) # 0, 1
            is_PII = search_PII(parse_file(file_path)) # 2
            is_file_sys_access = search_file_sys_access(parse_file(file_path)) # 3
            is_process_creation = search_file_process_creation(parse_file(file_path)) # 4
            is_network_access = search_network_access(parse_file(file_path)) # 5
            is_crypto_functionality = search_cryptographic_functionality(parse_file(file_path)) # 6
            is_data_encoding = search_data_encoding(parse_file(file_path)) # 7
            is_dynamic_code_generation = search_dynamic_code_generation(parse_file(file_path)) # 8
            is_package_installation = search_package_installation(parse_file(file_path)) # 9
            # check if the package was already processed
            if package_name not in visited_packages: 
                logging.info(f'package_name: {package_name}') 
                logging.debug(f"{package_name} was not visit yet")
                index = dirname.find("/package")
                logging.debug(f"dirname[:index]: {dirname[:index]}")
                is_geolocation = search_geolocation(dirname[:index]) # 10
                is_minified_code = search_minified_code(dirname[:index]) # 11
                is_has_no_content = search_packages_with_no_content(dirname[:index]) # 12
                longest_line = longest_line_in_the_package(dirname[:index]) # 13
                num_of_files = num_of_files_in_the_package(dirname[:index]) # 14
                has_license = does_contain_license(dirname[:index]) # 15
                visited_packages.add(package_name)
            else:
                logging.debug(f"package_features: {package_features}")
                is_geolocation = package_features[package_name][10]
                is_minified_code = package_features[package_name][11]
                is_has_no_content = package_features[package_name][12]
                longest_line = package_features[package_name][13] 
                num_of_files = package_features[package_name][14]
                has_license = package_features[package_name][15]
            label = packages_type # 16
            
            # create a new list of the current package's features
            new_inner_lst = [name, version, is_PII, is_file_sys_access, is_process_creation, 
                             is_network_access, is_crypto_functionality, is_data_encoding, 
                             is_dynamic_code_generation, is_package_installation, is_geolocation, is_minified_code, 
                             is_has_no_content, longest_line, num_of_files, has_license, label]
            
            # get the old feature list for the current package name
            old_inner_lst = package_features[package_name]
            
            logging.debug(f'new_inner_lst: {new_inner_lst[2:-7]}')
            logging.debug(f'old_inner_lst: {old_inner_lst[2:-7]}')
            # perform the bitwise operation between the new and old feature lists
            updated_inner_lst = bitwise_operation(new_inner_lst[2:-7], old_inner_lst[2:-7], '|')
            logging.debug(f'updated_inner_lst: {updated_inner_lst}')
            
            pre_list = [name, version]
            past_list = [is_geolocation, is_minified_code, is_has_no_content, longest_line, num_of_files, has_license, label]
            
            # update the value in the package_features dictionary with the updated feature list
            package_features[package_name] = pre_list + updated_inner_lst + past_list
    
    headers = ['package','version','PII','file_sys_access','file_process_creation',
    'network_access','cryptographic_functionality', 'data_encoding',
    'dynamic_code_generation','package_installation', 'geolocation', 'minified_code', 
    'no_content', 'longest_line', 'num_of_files', 'has_license', 'label']
    
    # define the path for the output CSV file
    # csv_file = '/Users/liozakirav/Documents/computer-science/fourth-year/Cyber/Tasks/Final-Project/amalfi-artifact/data/dataset/dataset-validation.csv'
    csv_file = 'dataset-validation.csv'
    # decide whether to write the data in append mode or write mode based on the input malicious flag
    method = 'a' if malicious else "w"
    
    # call the write_dict_to_csv function to write the package_features dictionary to the CSV file
    write_dict_to_csv(dict_data=package_features, csv_file=csv_file, headers=headers, method=method)
    
    # main_dir = '/Users/liozakirav/Documents/computer-science/fourth-year/Cyber/Tasks/Final-Project/amalfi-artifact/data/dataset'
    # write_each_package_and_version_to_csv_and_create_dir(package_features=package_features, main_dir=main_dir, header=headers[2:-1])
    

if __name__ == '__main__':
    # benign_path = '/Users/liozakirav/Documents/computer-science/fourth-year/Cyber/Tasks/Final-Project/amalfi-artifact/data/extracted-packages/validation_data/benign'
    # malicious_path = '/Users/liozakirav/Documents/computer-science/fourth-year/Cyber/Tasks/Final-Project/amalfi-artifact/data/extracted-packages/validation_data/malicious'
    # extract_features(benign_path, malicious=False)
    # extract_features(malicious_path, malicious=True)
    benign_path = '/Users/mdsiam/Desktop/Projects/amalfi-artifact/code/reproducer/packages'
    extract_features(benign_path, malicious=False)
    
