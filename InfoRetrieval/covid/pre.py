#very specific pre-processing program intended
#to clean up a covid dataset

import csv
import os
import re
import sys
import pandas as pd 


if __name__ == '__main__':

	#Takes in csv file
	with open('covidData.csv') as f:
		reader = csv.reader(f)
		rows = list(f)

		#Takes only relevant rows (naively may I add)
		dates = rows[0]
		elPaso = rows[2768]
		dates = dates.split(',') #Convert from str to list
		elPaso = elPaso.split(',')


		#primitive data deletion
		del dates[0:5]
		del elPaso[0:5]
		del dates[1:7]
		del elPaso[1:8]
	
	#Combines lists and turns them to a pandas dataFrame that has days on one row and the corresponding infections on the next row
	testList = list(zip(dates, elPaso))
	df = pd.DataFrame(testList)
	#print(df) #DEBUG

	#combine lists into key:value dict (key is date, value is num infections)
	#Not sure if this will ever be needed but leaving it here anyways
	infectionsPerDay = {} 
	for key in dates: 
		for value in elPaso: 
			infectionsPerDay[key] = value 
			elPaso.remove(value) 
			break 

	#print(infectionsPerDay) #DEBUG
	#print(dates)
	#print(elPaso)