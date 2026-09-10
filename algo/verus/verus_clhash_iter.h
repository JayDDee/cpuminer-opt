/* One iteration of the verusclhashv2_2 32-round loop: the only copy of it,
 * included by verus_clhash.c (1 lane) and verus_clhash_2way.c (2 lanes) so
 * neither can drift. No include guard -- the 2-way driver includes it twice per
 * iteration. The includer supplies these as plain locals (acc in a struct field
 * costs +5.1% on an A55): acc randomsource keyMask pbuf_copy fixrand fixrandex
 * g_prand g_prandex i */

		const uint64_t selector = _mm_cvtsi128_si64(acc);

		uint32_t prand_idx = (selector >> 5) & keyMask;
		uint32_t prandex_idx = (selector >> 32) & keyMask;
		// get two random locations in the key, which will be mutated and swapped
		__m128i *prand = randomsource + prand_idx;
		__m128i *prandex = randomsource + prandex_idx;

		// select random start and order of pbuf processing
		const __m128i *pbuf = pbuf_copy + (selector & 3);
		/* CSE across the 8 arms: every arm loads pbuf[0] and pbuf[+-1], and reads
		 * prand[0]/prandex[0] before its first store, so the journal loads serve
		 * both. The compiler may not do this -- it cannot know g_prand/g_prandex
		 * (key[552..615]) are disjoint from prand/prandex (key[0..keyMask]).
		 * Exact when prand == prandex. */
		const __m128i kprand = _mm_load_si128(prand);
		const __m128i kprandex = _mm_load_si128(prandex);
		const __m128i *pbufx = pbuf + ((selector & 1) ? -1 : 1);
		const __m128i pb0 = _mm_load_si128(pbuf);
		const __m128i pbx = _mm_load_si128(pbufx);

		_mm_store_si128(&g_prand[i], kprand);
		_mm_store_si128(&g_prandex[i], kprandex);
		fixrand[i] = prand_idx;
		fixrandex[i] = prandex_idx;

		switch (selector & 0x1c)
		{
		case 0:
		{
			const __m128i temp1 = kprandex;
			const __m128i temp2 = pbx;
			const __m128i add1 = _mm_xor_si128(temp1, temp2);
			const __m128i clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
			acc = _mm_xor_si128(clprod1, acc);

			const __m128i tempa1 = _mm_mulhrs_epi16(acc, temp1);
			const __m128i tempa2 = _mm_xor_si128(tempa1, temp1);

			const __m128i temp12 = kprand;
			_mm_store_si128(prand, tempa2);

			const __m128i temp22 = pb0;
			const __m128i add12 = _mm_xor_si128(temp12, temp22);
			const __m128i clprod12 = _mm_clmulepi64_si128(add12, add12, 0x10);
			acc = _mm_xor_si128(clprod12, acc);

			const __m128i tempb1 = _mm_mulhrs_epi16(acc, temp12);
			const __m128i tempb2 = _mm_xor_si128(tempb1, temp12);
			_mm_store_si128(prandex, tempb2);
			break;
		}
		case 4:
		{
			const __m128i temp1 = kprand;
			const __m128i temp2 = pb0;
			const __m128i add1 = _mm_xor_si128(temp1, temp2);
			const __m128i clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
			acc = _mm_xor_si128(clprod1, acc);
			const __m128i clprod2 = _mm_clmulepi64_si128(temp2, temp2, 0x10);
			acc = _mm_xor_si128(clprod2, acc);

			const __m128i tempa1 = _mm_mulhrs_epi16(acc, temp1);
			const __m128i tempa2 = _mm_xor_si128(tempa1, temp1);

			const __m128i temp12 = kprandex;
			_mm_store_si128(prandex, tempa2);

			const __m128i temp22 = pbx;
			const __m128i add12 = _mm_xor_si128(temp12, temp22);
			acc = _mm_xor_si128(add12, acc);

			const __m128i tempb1 = _mm_mulhrs_epi16(acc, temp12);
			_mm_store_si128(prand,_mm_xor_si128(tempb1, temp12));
			//_mm_store_si128(prand, tempb2);
			break;
		}
		case 8:
		{
			const __m128i temp1 = kprandex;
			const __m128i temp2 = pb0;
			const __m128i add1 = _mm_xor_si128(temp1, temp2);
			acc = _mm_xor_si128(add1, acc);

			const __m128i tempa1 = _mm_mulhrs_epi16(acc, temp1);
			const __m128i tempa2 = _mm_xor_si128(tempa1, temp1);

			const __m128i temp12 = kprand;
			_mm_store_si128(prand, tempa2);

			const __m128i temp22 = pbx;
			const __m128i add12 = _mm_xor_si128(temp12, temp22);
			const __m128i clprod12 = _mm_clmulepi64_si128(add12, add12, 0x10);
			acc = _mm_xor_si128(clprod12, acc);
			const __m128i clprod22 = _mm_clmulepi64_si128(temp22, temp22, 0x10);
			acc = _mm_xor_si128(clprod22, acc);

			const __m128i tempb1 = _mm_mulhrs_epi16(acc, temp12);
			const __m128i tempb2 = _mm_xor_si128(tempb1, temp12);
			_mm_store_si128(prandex, tempb2);
			break;
		}
		case 0xc:
		{
			const __m128i temp1 = kprand;
			const __m128i temp2 = pbx;
			const __m128i add1 = _mm_xor_si128(temp1, temp2);

			// cannot be zero here
			const int32_t divisor = (uint32_t)selector;

			acc = _mm_xor_si128(add1, acc);

			const int64_t dividend = _mm_cvtsi128_si64(acc);
			const __m128i modulo = _mm_cvtsi32_si128(dividend % divisor);
			acc = _mm_xor_si128(modulo, acc);

			const __m128i tempa1 = _mm_mulhrs_epi16(acc, temp1);
			const __m128i tempa2 = _mm_xor_si128(tempa1, temp1);

			if (dividend & 1)
			{
				const __m128i temp12 = kprandex;
				_mm_store_si128(prandex, tempa2);

				const __m128i temp22 = pb0;
				const __m128i add12 = _mm_xor_si128(temp12, temp22);
				const __m128i clprod12 = _mm_clmulepi64_si128(add12, add12, 0x10);
				acc = _mm_xor_si128(clprod12, acc);
				const __m128i clprod22 = _mm_clmulepi64_si128(temp22, temp22, 0x10);
				acc = _mm_xor_si128(clprod22, acc);

				const __m128i tempb1 = _mm_mulhrs_epi16(acc, temp12);
				const __m128i tempb2 = _mm_xor_si128(tempb1, temp12);
				_mm_store_si128(prand, tempb2);
			}
			else
			{
				_mm_store_si128(prand, kprandex);
				_mm_store_si128(prandex, tempa2);
				acc = _mm_xor_si128(pb0, acc);
			}
			break;
		}
		case 0x10:
		{
			// a few AES operations
			const __m128i *rc = prand;
			__m128i tmp;

			__m128i temp1 = pbx;
			__m128i temp2 = pb0;

			AES2(temp1, temp2, 0);
			MIX2(temp1, temp2);

			AES2(temp1, temp2, 4);
			MIX2(temp1, temp2);

			AES2(temp1, temp2, 8);
			MIX2(temp1, temp2);

			acc = _mm_xor_si128(temp2, _mm_xor_si128(temp1, acc));

			const __m128i tempa1 = kprand;
			const __m128i tempa2 = _mm_mulhrs_epi16(acc, tempa1);

			_mm_store_si128(prand, kprandex);
			_mm_store_si128(prandex, _mm_xor_si128(tempa1, tempa2));

			break;
		}
		case 0x14:
		{
			// we'll just call this one the monkins loop, inspired by Chris - modified to cast to uint64_t on shift for more variability in the loop
			__m128i tmp; // used by MIX2

			uint64_t rounds = selector >> 61; // loop randomly between 1 and 8 times
			__m128i *rc = prand;
			uint64_t aesroundoffset = 0;
			__m128i onekey;

			do
			{
				if (selector & (((uint64_t)0x10000000) << rounds))
				{
					//onekey = _mm_load_si128(rc++);
					const __m128i temp2 = rounds & 1 ? pb0 : pbx;
					const __m128i add1 = _mm_xor_si128(rc[0], temp2); rc++;
					const __m128i clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
					acc = _mm_xor_si128(clprod1, acc);
				}
				else
				{
					onekey = _mm_load_si128(rc++);
					__m128i temp2 = rounds & 1 ? pbx : pb0;
					AES2(onekey, temp2, aesroundoffset);
					aesroundoffset += 4;
					MIX2(onekey, temp2);
					acc = _mm_xor_si128(onekey, acc);
					acc = _mm_xor_si128(temp2, acc);
				}
			} while (rounds--);

			const __m128i tempa1 = kprand;
			const __m128i tempa2 = _mm_mulhrs_epi16(acc, tempa1);
			const __m128i tempa3 = _mm_xor_si128(tempa1, tempa2);

			const __m128i tempa4 = kprandex;
			_mm_store_si128(prandex, tempa3);
			_mm_store_si128(prand, tempa4);
			break;
		}
		case 0x18:
		{
			uint64_t rounds = selector >> 61; // loop randomly between 1 and 8 times
			__m128i *rc = prand;
			__m128i onekey;

			do
			{
				if (selector & (((uint64_t)0x10000000) << rounds))
				{
					//	onekey = _mm_load_si128(rc++);
					const __m128i temp2 = rounds & 1 ? pb0 : pbx;
					onekey = _mm_xor_si128(rc[0], temp2); rc++;
					// cannot be zero here, may be negative
					const int32_t divisor = (uint32_t)selector;
					const int64_t dividend = _mm_cvtsi128_si64(onekey);
					const __m128i modulo = _mm_cvtsi32_si128(dividend % divisor);
					acc = _mm_xor_si128(modulo, acc);
				}
				else
				{
					//	onekey = _mm_load_si128(rc++);
					__m128i temp2 = rounds & 1 ? pbx : pb0;
					const __m128i add1 = _mm_xor_si128(rc[0], temp2); rc++;
					onekey = _mm_clmulepi64_si128(add1, add1, 0x10);
					const __m128i clprod2 = _mm_mulhrs_epi16(acc, onekey);
					acc = _mm_xor_si128(clprod2, acc);
				}
			} while (rounds--);

			const __m128i tempa3 = kprandex;

			_mm_store_si128(prandex, onekey);
			_mm_store_si128(prand, _mm_xor_si128(tempa3, acc));
			//	_mm_store_si128(prand, tempa4);
			break;
		}
		case 0x1c:
		{
			const __m128i temp1 = pb0;
			const __m128i temp2 = kprandex;
			const __m128i add1 = _mm_xor_si128(temp1, temp2);
			const __m128i clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
			acc = _mm_xor_si128(clprod1, acc);

			const __m128i tempa1 = _mm_mulhrs_epi16(acc, temp2);
			const __m128i tempa2 = _mm_xor_si128(tempa1, temp2);

			const __m128i tempa3 = kprand;
			_mm_store_si128(prand, tempa2);

			acc = _mm_xor_si128(tempa3, acc);
			const __m128i temp4 = pbx;
			acc = _mm_xor_si128(temp4, acc);
			const __m128i tempb1 = _mm_mulhrs_epi16(acc, tempa3);
			*prandex = _mm_xor_si128(tempb1, tempa3);
			//	_mm_store_si128(prandex, tempb2);
			break;
		}
		}
	