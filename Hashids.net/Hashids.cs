using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace HashidsNet {
    /// <summary>
    /// Generate YouTube-like hashes from one or many numbers. Use hashids when you do not want to expose your database ids to the user.
    /// </summary>
    public class Hashids {
        public const string DefaultAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        public const string DefaultSeparators = "cfhistuCFHISTU";

        const int MinAlphabetLength = 16;
        const double SeparatorDivisor = 3.5;
        const double GuardDivisor = 12.0;

        readonly string _alphabet;
        readonly string _separators;
        readonly string _guards;
        readonly string _salt;
        readonly int _minHashLength;

        readonly Regex _guardsRegex;
        readonly Regex _separatorsRegex;
        static readonly Regex HexValidator = new Regex("^[0-9a-fA-F]+$", RegexOptions.Compiled);
        static readonly Regex HexSplitter = new Regex(@"[\w\W]{1,12}", RegexOptions.Compiled);

        /// <summary>
        /// Instantiates a new Hashids en/de-coder.
        /// </summary>
        public Hashids() : this("", 0, DefaultAlphabet, DefaultSeparators) {}

        /// <summary>
        /// Instantiates a new Hashids en/de-coder.
        /// </summary>
        public Hashids(string salt = "", int minHashLength = 0, string alphabet = DefaultAlphabet, string seps = DefaultSeparators) {
            if (string.IsNullOrWhiteSpace(alphabet))
                throw new ArgumentNullException("alphabet");

            _salt = salt;
            _alphabet = string.Join(string.Empty, alphabet.Distinct());
            _separators = seps;
            _minHashLength = minHashLength;

            if (_alphabet.Length < MinAlphabetLength)
                throw new ArgumentException(string.Format("alphabet must contain at least {0} unique characters.", MinAlphabetLength), "alphabet");

            // setup separators
            _separators = new String(_separators.Intersect(_alphabet.ToArray()).ToArray());

            // alphabet should not contain separators
            _alphabet = new String(_alphabet.Except(_separators.ToArray()).ToArray());

            _separators = ConsistentShuffle(_separators, _salt);

            if (_separators.Length == 0 || (_alphabet.Length / _separators.Length) > SeparatorDivisor) {
                var sepsLength = (int) Math.Ceiling(_alphabet.Length / SeparatorDivisor);
                if (sepsLength == 1) {
                    sepsLength = 2;
                }

                if (sepsLength > _separators.Length) {
                    var diff = sepsLength - _separators.Length;
                    _separators += _alphabet.Substring(0, diff);
                    _alphabet = _alphabet.Substring(diff);
                }
                else {
                    _separators = _separators.Substring(0, sepsLength);
                }
            }

            _separatorsRegex = new Regex(string.Concat("[", _separators, "]"), RegexOptions.Compiled);
            _alphabet = ConsistentShuffle(_alphabet, _salt);

            // setup guards
            var guardCount = (int) Math.Ceiling(_alphabet.Length / GuardDivisor);

            if (_alphabet.Length < 3) {
                _guards = _separators.Substring(0, guardCount);
                _separators = _separators.Substring(guardCount);
            }
            else {
                _guards = _alphabet.Substring(0, guardCount);
                _alphabet = _alphabet.Substring(guardCount);
            }

            _guardsRegex = new Regex(string.Concat("[", _guards, "]"), RegexOptions.Compiled);
        }

        /// <summary>
        /// Encrypts the provided hex string to a hashids hash.
        /// </summary>
        public virtual string EncodeHex(string hex) {
            if (!HexValidator.IsMatch(hex))
                return string.Empty;

            var numbers = new List<long>();
            var matches = HexSplitter.Matches(hex);

            foreach (Match match in matches) {
                var number = Convert.ToInt64(string.Concat("1", match.Value), 16);
                numbers.Add(number);
            }

            return Encode(numbers.ToArray());
        }

        /// <summary>
        /// Decodes the provided hash into a hex-string
        /// </summary>
        public virtual string DecodeHex(string hash) {
            var ret = new StringBuilder();
            var numbers = Decode(hash);

            foreach (var number in numbers) {
                ret.Append(string.Format("{0:X}", number).Substring(1));
            }

            return ret.ToString();
        }

        /// <summary>
        /// Encodes the provided numbers into a string
        /// </summary>
        public virtual string Encode(params long[] numbers) {
            var ret = new StringBuilder();
            var numbersHashInt = 0;
            if (numbers == null || numbers.Length == 0)
                return string.Empty;

            var alphabet = _alphabet;

            for (var i = 0; i < numbers.Length; i++) {
                numbersHashInt += (int) (numbers[i] % (i + 100));
            }

            var lottery = alphabet[numbersHashInt % alphabet.Length];
            ret.Append(lottery);

            for (var i = 0; i < numbers.Length; i++) {
                var number = numbers[i];
                var buffer = lottery + _salt + alphabet;

                alphabet = ConsistentShuffle(alphabet, buffer.Substring(0, alphabet.Length));
                StringBuilder last = Hash(number, alphabet);

                ret.Append(last);

                if (i + 1 < numbers.Length) {
                    number %= ((int) last[0] + i);
                    var sepsIndex = (int) (number % _separators.Length);

                    ret.Append(_separators[sepsIndex]);
                }
            }

            if (ret.Length < _minHashLength) {
                var guardIndex = (numbersHashInt + (int) ret[0]) % _guards.Length;
                var guard = _guards[guardIndex];
                ret.Insert(0, guard);

                if (ret.Length < _minHashLength) {
                    guardIndex = (numbersHashInt + (int) ret[2]) % _guards.Length;
                    guard = _guards[guardIndex];

                    ret.Append(guard);
                }
            }

            var halfLength = alphabet.Length / 2;
            while (ret.Length < _minHashLength) {
                alphabet = ConsistentShuffle(alphabet, alphabet);

                ret.Insert(0, alphabet.Substring(halfLength));
                ret.Append(alphabet.Substring(0, halfLength));

                var excess = ret.Length - _minHashLength;
                if (excess > 0) {
                    ret.Remove(0, excess / 2);
                    ret.Remove(_minHashLength, ret.Length - _minHashLength);
                }
            }

            return ret.ToString();
        }

        /// <summary>
        /// Decodes the provided hash
        /// </summary>
        public virtual long[] Decode(string hash) {
            if (string.IsNullOrWhiteSpace(hash))
                return new long[0];

            var alphabet = string.Copy(_alphabet);
            var ret = new List<long>();
            int i = 0;

            var hashBreakdown = _guardsRegex.Replace(hash, " ");
            var hashArray = hashBreakdown.Split(new[] {' '}, StringSplitOptions.RemoveEmptyEntries);

            if (hashArray.Length == 3 || hashArray.Length == 2) {
                i = 1;
            }

            hashBreakdown = hashArray[i];
            if (hashBreakdown[0] != default(char)) {
                var lottery = hashBreakdown[0];
                hashBreakdown = hashBreakdown.Substring(1);

                hashBreakdown = _separatorsRegex.Replace(hashBreakdown, " ");
                hashArray = hashBreakdown.Split(new[] {' '}, StringSplitOptions.RemoveEmptyEntries);

                for (var j = 0; j < hashArray.Length; j++) {
                    var subHash = hashArray[j];
                    var buffer = lottery + _salt + alphabet;

                    alphabet = ConsistentShuffle(alphabet, buffer.Substring(0, alphabet.Length));
                    ret.Add(Unhash(subHash, alphabet));
                }

                if (Encode(ret.ToArray()) != hash) {
                    ret.Clear();
                }
            }

            return ret.ToArray();
        }

        /// <summary>
        /// Decodes the provided hash and returns the first number only
        /// </summary>
        public long DecodeOne(string hash) {
            return Decode(hash).FirstOrDefault();
        }

        static StringBuilder Hash(long input, string alphabet) {
            var hash = new StringBuilder();

            do {
                hash.Insert(0, alphabet[(int) (input % alphabet.Length)]);
                input = input / alphabet.Length;
            } while (input > 0);

            return hash;
        }

        static long Unhash(string input, string alphabet) {
            var number = 0L;

            for (var i = 0; i < input.Length; i++) {
                var pos = alphabet.IndexOf(input[i]);
                number += (long) (pos * Math.Pow(alphabet.Length, input.Length - i - 1));
            }

            return number;
        }

        static string ConsistentShuffle(string alphabet, string salt) {
            if (string.IsNullOrWhiteSpace(salt))
                return alphabet;

            int v = 0, p = 0, n = 0, j = 0;

            for (var i = alphabet.Length - 1; i > 0; i--, v++) {
                v %= salt.Length;
                p += n = (int) salt[v];
                j = (n + v + p) % i;

                var temp = alphabet[j];
                alphabet = alphabet.Substring(0, j) + alphabet[i] + alphabet.Substring(j + 1);
                alphabet = alphabet.Substring(0, i) + temp + alphabet.Substring(i + 1);
            }

            return alphabet;
        }
    }
}
