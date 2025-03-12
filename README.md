# Static-Analysis-For-PE


The first template of the script.
   -- The PE file comes as an command line argument.
   -- First step is to check the file type.
   -- Second step is to use the entropy level of the file (using ent).
   -- Third step is to extract the readable strings from the PE and save those strings in a file.
   -- Fourth step, identify imported DLLs.
   -- Fifth step is to check for branching, but for the moment I have some issues with this.
   -- Sixth step is checking for dead code.
   -- Seventh step it's just for test purpose, just open the DIE(Detect it Easy) with the PE file.
   -- Eighth step, disassemble using objdump and save it to a file.
