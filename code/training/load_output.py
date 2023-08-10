import pickle

file = 'output.bin'

with open(file, "rb") as f:
    obj = pickle.load(f)
    
print(obj)