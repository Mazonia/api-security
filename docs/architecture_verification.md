# MazAPI Architecture Verification Notes

This document provides runtime verification and architectural references for the MazAPI security testing suite.

## Security Baseline
- API1: BOLA verification via authorization filter.
- API2: Cryptographic token validation with HMAC-SHA256 signature enforcement.
- API3: Parameter filtering against Mass Assignment exploitation.
- API4: Distributed sliding-window rate limiting.