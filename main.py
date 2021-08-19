import re
import sys
import string
import collections

# frequency of each English letter 
english_frequences = [0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
					  0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
					  0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
					  0.00978, 0.02360, 0.00150, 0.01974, 0.00074]
alphabet = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')

# Frequency analysis on the sequence of the ciphertext
# The Chi-Squared Statistic measure how similar to English the sequence is
# Return a letter which is the Ceasar cipher's key of this sequence
def freq_analysis(sequence):
    	
    # array to store 26 chi-squareds corresponding to 26 possbile shifts  
	all_chi_squareds = [0] * 26
	for i in range(26):
		chi_squared_sum = 0.0

		# list of characters in the sequence
		sequence_characters = [chr(((ord(sequence[j])-97-i)%26)+97) for j in range(len(sequence))]
		
		# initialize a - array to store number of time each letter occurs
		a = [0] * 26
		
		# count the number of times each character occurs
		for l in sequence_characters:
			a[ord(l) - ord('a')] += 1

		# divide the array by the length of the sequence to get the frequency percentages
		for j in range(26):
			a[j] *= (1.0/float(len(sequence)))

		# Chi-squared Statistic formula
		for j in range(26):
			chi_squared_sum+=((a[j] - float(english_frequences[j]))**2)/float(english_frequences[j])

		# add to the array of chi-squareds
		all_chi_squareds[i] = chi_squared_sum

	# return the letter corresponding to the smallest chi-squared
	shift = all_chi_squareds.index(min(all_chi_squareds))
	return chr(shift+97)

def get_key(ciphertext, key_length):
	key = ''

	# Find each letter of the key
	for i in range(key_length):
		sequence=""

		# divide the ciphertext into sequences
		for j in range(0,len(ciphertext[i:]), key_length):
			sequence+=ciphertext[i+j]
		
		# add letter to the key
		key+=freq_analysis(sequence)

	return key

# Returns the plaintext given the ciphertext and a key
def decrypt(ciphertext, key):
    	
	# Creates an array of the ascii values of the ciphertext and the key
	cipher_ascii = [ord(letter) for letter in ciphertext]
	key_ascii = [ord(letter) for letter in key]
	plain_ascii = []

	# Turns each ascii value of the ciphertext into the ascii value of the plaintext
	for i in range(len(cipher_ascii)):
		plain_ascii.append(((cipher_ascii[i]-key_ascii[i % len(key)]) % 26) +97)

	# Turns the array of ascii values into characters
	plaintext = ''.join(chr(i) for i in plain_ascii)
	return plaintext

# Returns Index of Coincidence of ciphertext
def getIC(ciphertext):
    frequency_sum = 0.0

    # use I.C formula for letter in alphabet:
    for letter in alphabet:
        frequency_sum+= ciphertext.count(letter) * (ciphertext.count(letter)-1)

    # use I.C formula
    ic = frequency_sum/(len(ciphertext)*(len(ciphertext)-1))
    return ic

# Get encoded from input file
cipher_file  = open( 'input.txt' , 'rb')  
original_text  = cipher_file.read()

# Remove any characters except alphabet letters and convert capital letters to lowercase
ctext = original_text.translate(string.maketrans("",""), string.punctuation)
ctext = ''.join(filter(alphabet.__contains__, ctext))
ctext  = "".join( 
                        [x.lower() for x in ctext.split() \
                                   if  x.isalpha() ]
                     )


# Get estimated key length by Friedman method
ctext_len = len(ctext)
frequency_sum = 0.0
ic = getIC(ctext)
est_klen = (0.027*ctext_len)/((ctext_len-1)*ic + 0.065 - 0.038*ctext_len)
est_klen = int (est_klen)

# Start searching for the right key length from the estimated key length found above
# init 
klen_lo = est_klen
klen_hi = est_klen
while True:
    key = get_key(ctext, klen_lo)
    plaintext = decrypt(ctext, key)
    ic = getIC(plaintext)
    if ic >= 0.056 and ic <= 0.075 :
        break
    key = get_key(ctext, klen_hi)
    plaintext = decrypt(ctext, key)
    ic = getIC(plaintext)
    if ic >= 0.056 and ic <= 0.075 :
        break
    if klen_lo > 1:
        klen_lo = klen_lo-1
    klen_hi+=1

plaintext = decrypt(ctext, key)

res = ""
k=0
i=0
while True:
    # add characters other than alphabet
    if not original_text[i] in alphabet:
        j = i
        while not original_text[j] in alphabet:
            res = res + original_text[j]
            j+=1
        i = j
	# capitalize letters which is uppercase in original text
    if original_text[i].isupper():
        res = res + plaintext[k].capitalize()
        k+=1
        i+=1
        if k == len(plaintext):
            break
    else:
        res = res + plaintext[k]
        k+=1
        i+=1
        if k == len(plaintext):
            break

f = open("output.txt", "a")
f.truncate(0)
f.write("Key: {}".format(key))
f.write("\n")
f.write("Text:")
f.write("\n");
f.write(res)
f.close()