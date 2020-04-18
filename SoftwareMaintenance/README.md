# Purpose

This repository contains programs that data mine information from
public repositories in order to answer some hypothesis I created regarding the nature of larger corperations and the cyclomatic complexity of their code. This was done as part of a final projectin a course on Software Maintenance that, at the time of writing this, I am taking as part of my graduate coursework.

# Hypothesis
These are the questions that I plan to solve utilizign the scripts found within this repository. Note that while this repository contains scripts to extract the needed information from other repositories: further analysis is likely needed to refine the information into a solution for the questions.

1. What is the general distribution of the cyclomatic complexity?
	* This Question is answered by cyclo-distro (Roughly). The information outputted to the csv file in this directory and then visualized using excel.
1. Who has removed the most lines of code? Have they added more code than they have removed?
	* This Question is answered by mostRemoved.py
1. Are there any type of security issues that are recurring within the repository?
	* This question is not solved by any of the programs in this repository, instead I utilized Gitrob (https://github.com/michenriksen/gitrob)


# Legal Stuff
All scripts within this repository are my own with the exception of segments pulled from the repository that I analyzed (The NSA's Ghidra repository). 

All of the scripts created here should be also considered open source, just please don't plagiarize :)

