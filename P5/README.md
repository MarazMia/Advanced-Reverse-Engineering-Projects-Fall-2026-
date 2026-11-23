# project 5
## About
Python program to create blocks from ELF contained object code
Used earlier projects without structuring or nesting
1. locate the blocks
2. instaniate a class for each block with
   a. starting address of the block
   b. ending address of the block
   c. set of registered read in entering -- i wonder if it should exclude registers made live by the block - i am going to do that
       * if a register is read, but is not in the written list, then it is eligible for the live at entry in list
   d. set of registered written during the block
3. print out in alphabetical order the live on entry registers at the address of the block

## Built With
python 3.14
wsl linux

 ## Author
 Dennis N Jump
 
