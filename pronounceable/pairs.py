#!/usr/bin/python

from collections import defaultdict
from json import dump

keysize = 3

with open('google-10000-english-usa.txt') as f:
	words = list(filter(lambda s: len(s) > 0 and s.isalpha(), map(lambda s: s.strip().lower(), f.readlines())))

def compute_adjacency_list():
	letters = defaultdict(set)
	for word in words:
		for i in xrange(len(word) - keysize):
			letters[word[i:i+keysize]].add(word[i+keysize])

	def cleanup(letters):
		for l in letters:
			letters[l] = filter(lambda c: (l[1:] + c) in letters, letters[l])
			letters = {l: letters[l] for l in letters if len(letters[l]) > 0}
		return letters

	last = sum(map(lambda v: len(v), letters.values()))
	letters = cleanup(letters)
	while sum(map(lambda v: len(v), letters.values())) != last:
		last = sum(map(lambda v: len(v), letters.values()))
		letters = cleanup(letters)
	letters = {l: "".join(letters[l]) for l in letters if len(letters[l]) > 0}

	return letters

def total_number(letters, length):
	def recurse(password):
		if len(password) >= length:
			return 1
		if not password:
			total = 0
			for first in letters:
				total += recurse(first)
			return total
		else:
			total = 0
			for c in letters[password[-keysize:]]:
				total += recurse(password + c)
			return total
	return recurse("")


# letters = compute_adjacency_list()
# print total_number(letters, 6)
# dump(letters, open("adjacency.json", "w"), separators=(',', ':'))