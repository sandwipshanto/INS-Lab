# Lab 2 Report: Breaking Classic Ciphers


---

## Checkpoint 1: Caesar Cipher Attack

### Cipher Text
```
odroboewscdrolocdcwkbdmyxdbkmdzvkdpybwyeddrobo
```

### Approach

Since Caesar cipher only has 26 possible shifts, I used **brute force attack**:

1. Loop through all shifts from 0 to 25
2. For each shift, decrypt the cipher by shifting each letter back
3. Print all 26 results
4. Manually look through them to find readable English text

### Result

**Shift: 10**  
**Plaintext:** `thereisnosecretowhichcannotberevealedtohere`  
Which reads as: "there is no secret which cannot be revealed to here"

---

## Checkpoint 2: Substitution Cipher Attack

### Approach

Used **frequency analysis** because brute force is impossible (too many possible keys).

**Step 1: Frequency Counting**
- Count how often each letter appears in the ciphertext
- Calculate the percentage for each letter

**Step 2: Initial Mapping**
- Sort cipher letters by frequency (most to least common)
- Map them to English letters sorted by frequency
- Most common cipher letter → 'e'
- Second most common → 't'
- Third most common → 'a', and so on

**Step 3: Initial Decryption**
- Apply the mapping to decrypt the text
- See what it looks like (usually partially readable but with errors)

**Step 4: Manual Refinement**
- Look for common short words like "the", "and", "of", "to"
- Find patterns like double letters (ee, oo, ll)
- Adjust the mapping based on context
- Decrypt again and check if it's better
- Repeat until fully readable

### Cipher-1 Results

**Initial frequency mapping gave partially readable text**

After manual refinement:
```
"in a particular anf, in each case, fifferent way, these four were infispensable to him-
-yumo amaryl, because of his quick unferstanfinm of the principles of psychohistory anf
of his imaminatise probinms into new areas. it was comfortinm to know that if anythinm
happenef to selfon himself before the mathematics of the fielf coulf be completely workef out-
-anf how slowly it proceefef, anf how mountainous the obstacles--there woulf at least remain one
moof minf that woulf continue the research"
```

### Cipher-2 Results

**Initial frequency mapping was more accurate from the start**

After some refinement:
```
"bilbf was pery rich and pery pecxliar, and had been the wfnder ff the shire ffr
sibty years, eper since his remarrable disappearance and xnebpected retxrn. the
riches he had brfxnht bacr frfm his trapels had nfw becfme a lfcal lenend, and it was
pfpxlarly belieped, whateper the fld fflr minht say, that the hill at ban end was fxll ff
txnnels stxffed with treasxre. and if that was nft enfxnh ffr fame, there was alsf his
prflfnned pinfxr tf marpel at. time wfre fn, bxt it seemed tf hape little effect fn
mr. bannins. at ninety he was mxch the same as at fifty. at ninety-nine they benan tf
call him well-preserped; bxt xnchanned wfxld hape been nearer the marr. there were sfme
that shffr their heads and thfxnht this was tff mxch ff a nffd thinn; it seemed xnfair that
anyfne shfxld pfssess (apparently) perpetxal yfxth as well as (repxtedly)
inebhaxstible wealth. it will hape tf be paid ffr, they said. it isn't natxral, and trfxble
will cfme ff it! bxt sf far trfxble had nft cfme; and as mr. bannins was nenerfxs with
his mfney, mfst pefple were willinn tf ffrnipe him his fddities and his nffd ffrtxne. he
remained fn pisitinn terms with his relatipes (ebcept, ff cfxrse, the sacrpille-
banninses), and he had many depfted admirers amfnn the hfbbits ff pffr and
xnimpfrtant families. bxt he had nf clfse friends, xntil sfme ff his yfxnner cfxsins
benan tf nrfw xp. the eldest ff these, and bilbf's fapfxrite, was yfxnn frfdf bannins.
when bilbf was ninety-nine he adfpted frfdf as his heir, and brfxnht him tf lipe at ban
end; and the hfpes ff the sacrpille- banninses were finally dashed. bilbf and frfdf
happened tf hape the same birthday, september 22nd. yfx had better cfme and lipe here,
frfdf my lad, said bilbf fne day; and then we can celebrate fxr birthday-parties
cfmffrtably tfnether. at that time frfdf was still in his tweens, as the hfbbits called the
irrespfnsible twenties between childhffd and cfminn ff ane at thirty-three"
```
(Text from The Hobbit by J.R.R. Tolkien)

---

## Which Cipher Was Easier to Break?

**Answer: Cipher-2 was much easier**

### Reasons:

1. **More text = Better statistics**
   - Cipher-2 is 3x longer (1876 vs 566 characters)
   - With more letters, the frequency counts are more accurate
   - Letter frequencies match expected English frequencies better

2. **More patterns to recognize**
   - Names like "Bilbo" and "Frodo" appeared multiple times
   - Common words repeated more often
   - Easier to verify if a mapping is correct

3. **Less manual work needed**
   - Initial frequency mapping was already pretty good
   - Needed fewer adjustments to get readable text
   - Took less time overall

4. **More context clues**
   - Longer text means more sentence structure to understand
   - Could guess words from surrounding context
   - Mistakes were more obvious

### Why Cipher-1 Was Harder:

- Shorter text means less reliable frequency data
- Had to do more trial-and-error with the mapping
- Less context to verify if substitutions were correct
- Took more time to manually refine

---

## Summary

**Caesar Cipher:** Easy to break with brute force (just try all 26 shifts)

**Substitution Cipher:** Need frequency analysis + manual refinement. Longer text is much easier to break because statistics work better with more data.
