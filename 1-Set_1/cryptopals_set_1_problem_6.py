import base64
# compile using $python3 fileName.py
with open("cryptopals_set_1_problem_6_dataset.txt") as file:
        ciphertext = base64.standard_b64decode(file.read())
        print(ciphertext.hex());
