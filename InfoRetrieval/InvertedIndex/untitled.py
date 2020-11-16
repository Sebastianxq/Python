from nltk.stem import PorterStemmer
from nltk.tokenize import word_tokenize 

sentence = """Interface OR System
Sensitive AND Information
Semantic OR Web
Retrieval OR Query
We AND Present
Siloed OR system
Labeled AND Data
Pseudo OR Feedback
Search AND Expertise
Relevance AND Estimation
Ranking OR Model
Seeking AND Sensemaking 
San AND Diego
"""

words = word_tokenize(sentence)
ps = PorterStemmer()
for word in words:
	word = ps.stem(word) #Stems words (Cuts off prefix and suffix)

print(words)