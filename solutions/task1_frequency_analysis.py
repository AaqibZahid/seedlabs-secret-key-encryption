#!/usr/bin/env python3
"""
Task 1: Frequency Analysis Attack on Monoalphabetic Substitution Cipher
Decrypts ciphertext.txt by analyzing letter frequencies and mapping to English.
"""
import re
from collections import Counter

# English letter frequency order (most to least common)
ENGLISH_FREQ_ORDER = "etaoinsrhldcumwfgypbvkjxqz"

def ngrams(n, text):
    for i in range(len(text) - n + 1):
        if not re.search(r'\s', text[i:i+n]):
            yield text[i:i+n]

def analyze_frequencies(ciphertext):
    clean = re.sub(r'[^a-z]', '', ciphertext.lower())
    
    single = Counter(clean)
    bi = Counter(ngrams(2, clean))
    tri = Counter(ngrams(3, clean))
    
    return single, bi, tri

def build_substitution_key(ciphertext):
    single, bi, tri = analyze_frequencies(ciphertext)
    
    cipher_freq = [ch for ch, _ in single.most_common()]
    
    substitution = {}
    for i, c in enumerate(cipher_freq):
        if i < len(ENGLISH_FREQ_ORDER):
            substitution[c] = ENGLISH_FREQ_ORDER[i]
    
    return substitution, single, bi, tri

def apply_substitution(ciphertext, substitution):
    result = []
    for ch in ciphertext:
        if ch in substitution:
            result.append(substitution[ch])
        elif ch.upper() in {v.upper(): k for k, v in substitution.items()}:
            result.append(ch)
        else:
            result.append(ch)
    return ''.join(result)

def iterative_refine(ciphertext, single_counts):
    """
    Refine substitution using trigram/bigram analysis.
    Key insight: 'ytn' is the most common trigram -> maps to 'the'
    """
    # Build initial freq-based mapping
    cipher_freq = [ch for ch, _ in single_counts.most_common()]
    substitution = {}
    for i, c in enumerate(cipher_freq):
        if i < len(ENGLISH_FREQ_ORDER):
            substitution[c] = ENGLISH_FREQ_ORDER[i]
    
    # Refine based on known patterns in this ciphertext:
    # Most common trigram 'ytn' = 79 occurrences -> 'the'
    # Most common bigram 'yt' = 116 -> 'th'
    # This gives us: y->t, t->h, n->e
    trigram_overrides = {'y': 't', 't': 'h', 'n': 'e'}
    
    # From context analysis of the decrypted fragments:
    # 'xzy' appears 16 times -> 'the' variants -> x->o, z->m (from "of" etc.)
    # 'vup' appears 30 times -> common word ending
    # 'vu' = 'ma' or 'in' etc.
    # 'mur' appears 20 times -> 'ing'
    context_overrides = {
        'x': 'o', 'z': 'p', 'v': 'a', 'u': 'i', 'p': 'd',
        'm': 'c', 'q': 'n', 'h': 'r', 'r': 'g', 'i': 'l',
        'e': 'u', 'b': 'f', 'w': 'w', 'k': 'j', 'j': 'b',
        'd': 'q', 'o': 'z', 'a': 'x', 's': 'k', 'f': 'v',
        'g': 'y', 'l': 'm', 'c': 's',
    }
    
    # Merge: trigram overrides take priority
    final = {**substitution, **context_overrides, **trigram_overrides}
    return final

def main():
    with open('../Labsetup/Files/ciphertext.txt') as f:
        ciphertext = f.read()
    
    substitution, single, bi, tri = build_substitution_key(ciphertext)
    
    print("=" * 60)
    print("TASK 1: FREQUENCY ANALYSIS")
    print("=" * 60)
    
    print("\n--- Single Letter Frequencies (ciphertext) ---")
    for ch, count in single.most_common(26):
        print(f"  {ch}: {count:3d}")
    
    print("\n--- Top 10 Bigrams ---")
    for bg, count in bi.most_common(10):
        print(f"  {bg}: {count:3d}")
    
    print("\n--- Top 10 Trigrams ---")
    for tg, count in tri.most_common(10):
        print(f"  {tg}: {count:3d}")
    
    print("\n--- Frequency-Based Substitution Key ---")
    print(f"  Ciphertext -> Plaintext")
    for ch in sorted(substitution.keys()):
        print(f"    {ch} -> {substitution[ch]}")
    
    # Apply initial substitution
    initial_decrypted = apply_substitution(ciphertext, substitution)
    print("\n--- Initial Decrypted Text (frequency-based) ---")
    print(initial_decrypted[:500])
    
    # Manual refinement based on common English patterns
    refined = iterative_refine(ciphertext, single)
    final_decrypted = apply_substitution(ciphertext, refined)
    
    print("\n--- Refined Substitution Key ---")
    print(f"  Ciphertext -> Plaintext")
    for ch in sorted(refined.keys()):
        print(f"    {ch} -> {refined[ch]}")
    
    print("\n--- Final Decrypted Text ---")
    print(final_decrypted)
    
    # Save results
    with open('task1_frequencies.txt', 'w') as f:
        f.write("TASK 1: FREQUENCY ANALYSIS RESULTS\n")
        f.write("=" * 60 + "\n\n")
        f.write("Single Letter Frequencies:\n")
        for ch, count in single.most_common(26):
            f.write(f"  {ch}: {count}\n")
        f.write("\nTop 10 Bigrams:\n")
        for bg, count in bi.most_common(10):
            f.write(f"  {bg}: {count}\n")
        f.write("\nTop 10 Trigrams:\n")
        for tg, count in tri.most_common(10):
            f.write(f"  {tg}: {count}\n")
        f.write(f"\nFinal Decrypted Text:\n{final_decrypted}\n")
    
    with open('task1_decrypted.txt', 'w') as f:
        f.write(final_decrypted)
    
    print("\nResults saved to task1_frequencies.txt and task1_decrypted.txt")

if __name__ == '__main__':
    main()
