MD5 Collision Demonstration
============================

Files
-----
- collision_a.bin  (128 bytes)
- collision_b.bin  (128 bytes)

Both files have the same MD5 digest but different SHA-256 digests.

This demonstrates the birthday attack on MD5's collision resistance,
first shown by Wang, Feng, Lai, and Yu (CRYPTO 2004).

Historical Incidents
--------------------
1. Rogue CA Certificate (2008): Researchers created a fraudulent CA certificate
   using an MD5 chosen-prefix collision (Stevens et al.).

2. Flame Malware (2012): Microsoft's Terminal Services certificate was forged
   using an MD5 collision, allowing Flame to appear as legitimate Microsoft software.

3. MD5 is considered cryptographically broken for digital signatures and
   certificates. It should NEVER be used for collision-resistant purposes.

Why This Matters
----------------
- Collision resistance: MD5 is BROKEN (collision found in seconds on a laptop)
- Preimage resistance: MD5 is NOT broken for preimage (no known practical attack)
- Lesson: Always use SHA-256 or SHA-3 for collision-resistant hashing

Usage
-----
  hashtool md5-demo --dir demo/md5_collision

This will compute and compare MD5 and SHA-256 digests of both files.
