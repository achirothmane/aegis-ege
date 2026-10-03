package evidenceverify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
)

// The succession profile uses ASCII-keyed JSON objects and exact nonnegative
// integers <= 2^53-1. It intentionally does not implement general floating point
// JCS. Unsupported values fail closed instead of silently changing an oracle.
func successionCanonical(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var parsed any
	if err := d.Decode(&parsed); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	var emit func(any) error
	emit = func(v any) error {
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				for _, c := range k {
					if c > 127 {
						return fmt.Errorf("non-ASCII canonical key outside succession profile")
					}
				}
				keys = append(keys, k)
			}
			sort.Strings(keys)
			b.WriteByte('{')
			for i, k := range keys {
				if i > 0 {
					b.WriteByte(',')
				}
				if err := emit(k); err != nil {
					return err
				}
				b.WriteByte(':')
				if err := emit(x[k]); err != nil {
					return err
				}
			}
			b.WriteByte('}')
		case []any:
			b.WriteByte('[')
			for i, item := range x {
				if i > 0 {
					b.WriteByte(',')
				}
				if err := emit(item); err != nil {
					return err
				}
			}
			b.WriteByte(']')
		case string:
			for _, c := range x {
				if c > 127 {
					return fmt.Errorf("non-ASCII canonical value outside succession profile")
				}
			}
			var s bytes.Buffer
			e := json.NewEncoder(&s)
			e.SetEscapeHTML(false)
			if err := e.Encode(x); err != nil {
				return err
			}
			b.Write(bytes.TrimSuffix(s.Bytes(), []byte("\n")))
		case json.Number:
			n, err := strconv.ParseUint(string(x), 10, 64)
			if err != nil || n > 1<<53-1 {
				return fmt.Errorf("number outside exact succession integer profile")
			}
			b.WriteString(strconv.FormatUint(n, 10))
		case bool:
			if x {
				b.WriteString("true")
			} else {
				b.WriteString("false")
			}
		case nil:
			b.WriteString("null")
		default:
			return fmt.Errorf("unsupported canonical value")
		}
		return nil
	}
	if err := emit(parsed); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func successionDigest(prefix string, value any) string {
	canonical, err := successionCanonical(value)
	if err != nil {
		return ""
	}
	return ContentDigest(append([]byte(prefix), canonical...))
}
