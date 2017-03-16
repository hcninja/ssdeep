/*
	Copyright 2017 - José González (josef@hackercat.ninja)

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	   http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package ssdeep

// Levenshtein distance between two strings
func LevenshteinDistance(str1, str2 string) int {
	var cost, lastdiag, olddiag int
	s1 := []rune(str1)
	s2 := []rune(str2)

	lenS1 := len(s1)
	lenS2 := len(s2)

	column := make([]int, lenS1+1)

	for y := 1; y <= lenS1; y++ {
		column[y] = y
	}

	for x := 1; x <= lenS2; x++ {
		column[0] = x
		lastdiag = x - 1
		for y := 1; y <= lenS1; y++ {
			olddiag = column[y]
			cost = 0
			if s1[y-1] != s2[x-1] {
				cost = 1
			}
			column[y] = min(
				column[y]+1,
				column[y-1]+1,
				lastdiag+cost)
			lastdiag = olddiag
		}
	}
	return column[lenS1]
}

func min(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
	} else {
		if b < c {
			return b
		}
	}
	return c
}
