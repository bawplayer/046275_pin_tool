Our solution is based on our assignment B.
1. Persistency - On assignment B we assumed the code is loaded with ASLR disabled.
Since this assumption has been voided by Gadi, we have modified our solution to "remember" edges' and BBLs' offset relative to the lowest address of their image, instead of absolute address. Excluding cases where a routine absolute address - in the current execution - cannot be inferred, the output still shows the routines' and BBLs' absolute address (not offsets!), which are valid in reference to the last execution.
2. tc - We used Gadi's tool for this assignment, with little modifications.
First, we allocate the tc memory only on our first call to the image's instrument.
As soon as we completed to pin-point all the data that is required for translation of the 10 hotest routines, we proceed to the chaining stage and compelete the tranlation. Other than find_candidate_rtns_for_translation(), in our solution, all functions under the image instrument are supposed to be called once at most.
Note A: We assumed the main image is also the 1st image to be loaded.
Note B: We assumed at least 10 routines in program.
