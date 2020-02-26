# What is KWIC?
KWIC is a "Key Word In Context" program that works for any arbitraty text file. It takes a input file and outputs all the possible circular shifts of the lines found within that file


## Example
  ##### Input
   - Pipes and Filters
  
  ##### Output
   * and Filters Pipes
   * Filters Pipes and 
   * Pipes and Filters
    

# How to run
This script can be run from the command line and, although I haven't explicitly tested it: any IDE that can run python3. You MUST either specify the entire path to the text file that you want to enter or have the text file within the same directory as the script.  The script can be run with the following command:

> ./KWIC.py

# Additional
Initially I drafted a algorithm that generated all combinations of each word in the line, this algorithm wasn't a requirement but I misinterpreted the prompt and decided I might as well leave it in here since I already created and debugged it. 



