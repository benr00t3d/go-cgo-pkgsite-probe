package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode/utf8"
)

type wireField struct {
	number int
	wire   int
	value  []byte
	varint uint64
}

type fieldSummary struct {
	Name       string  `json:"name"`
	Number     uint64  `json:"number"`
	Label      string  `json:"label,omitempty"`
	Type       string  `json:"type,omitempty"`
	TypeName   string  `json:"typeName,omitempty"`
	OneofIndex *uint64 `json:"oneofIndex,omitempty"`
}

type messageSummary struct {
	Name     string           `json:"name"`
	Fields   []fieldSummary   `json:"fields,omitempty"`
	Messages []messageSummary `json:"messages,omitempty"`
	Enums    []enumSummary    `json:"enums,omitempty"`
}

type enumValueSummary struct {
	Name   string `json:"name"`
	Number uint64 `json:"number"`
}

type enumSummary struct {
	Name   string             `json:"name"`
	Values []enumValueSummary `json:"values,omitempty"`
}

type methodSummary struct {
	Name            string `json:"name"`
	InputType       string `json:"inputType"`
	OutputType      string `json:"outputType"`
	ClientStreaming bool   `json:"clientStreaming,omitempty"`
	ServerStreaming bool   `json:"serverStreaming,omitempty"`
}

type serviceSummary struct {
	Name    string          `json:"name"`
	Methods []methodSummary `json:"methods,omitempty"`
}

type fileSummary struct {
	Name         string           `json:"name"`
	Package      string           `json:"package,omitempty"`
	Dependencies []string         `json:"dependencies,omitempty"`
	Messages     []messageSummary `json:"messages,omitempty"`
	Enums        []enumSummary    `json:"enums,omitempty"`
	Services     []serviceSummary `json:"services,omitempty"`
}

func consumeField(data []byte, offset int) (wireField, int, bool) {
	if offset >= len(data) {
		return wireField{}, offset, false
	}
	key, n := binary.Uvarint(data[offset:])
	if n <= 0 {
		return wireField{}, offset, false
	}
	offset += n
	field := wireField{number: int(key >> 3), wire: int(key & 7)}
	if field.number <= 0 {
		return wireField{}, offset, false
	}
	switch field.wire {
	case 0:
		value, size := binary.Uvarint(data[offset:])
		if size <= 0 {
			return wireField{}, offset, false
		}
		field.varint = value
		offset += size
	case 1:
		if offset+8 > len(data) {
			return wireField{}, offset, false
		}
		field.value = data[offset : offset+8]
		offset += 8
	case 2:
		length, size := binary.Uvarint(data[offset:])
		if size <= 0 || length > uint64(len(data)) {
			return wireField{}, offset, false
		}
		offset += size
		if length > uint64(len(data)-offset) {
			return wireField{}, offset, false
		}
		field.value = data[offset : offset+int(length)]
		offset += int(length)
	case 5:
		if offset+4 > len(data) {
			return wireField{}, offset, false
		}
		field.value = data[offset : offset+4]
		offset += 4
	default:
		return wireField{}, offset, false
	}
	return field, offset, true
}

func fields(data []byte) ([]wireField, bool) {
	var result []wireField
	for offset := 0; offset < len(data); {
		field, next, ok := consumeField(data, offset)
		if !ok || next <= offset {
			return nil, false
		}
		result = append(result, field)
		offset = next
	}
	return result, true
}

func firstString(values []wireField, number int) string {
	for _, value := range values {
		if value.number == number && value.wire == 2 && utf8.Valid(value.value) {
			return string(value.value)
		}
	}
	return ""
}

func firstVarint(values []wireField, number int) (uint64, bool) {
	for _, value := range values {
		if value.number == number && value.wire == 0 {
			return value.varint, true
		}
	}
	return 0, false
}

func labelName(value uint64) string {
	switch value {
	case 1:
		return "optional"
	case 2:
		return "required"
	case 3:
		return "repeated"
	default:
		return fmt.Sprintf("label_%d", value)
	}
}

func typeName(value uint64) string {
	names := map[uint64]string{
		1: "double", 2: "float", 3: "int64", 4: "uint64", 5: "int32",
		6: "fixed64", 7: "fixed32", 8: "bool", 9: "string", 10: "group",
		11: "message", 12: "bytes", 13: "uint32", 14: "enum", 15: "sfixed32",
		16: "sfixed64", 17: "sint32", 18: "sint64",
	}
	if name := names[value]; name != "" {
		return name
	}
	return fmt.Sprintf("type_%d", value)
}

func summarizeField(data []byte) (fieldSummary, bool) {
	values, ok := fields(data)
	if !ok {
		return fieldSummary{}, false
	}
	name := firstString(values, 1)
	number, hasNumber := firstVarint(values, 3)
	if name == "" || !hasNumber {
		return fieldSummary{}, false
	}
	result := fieldSummary{Name: name, Number: number, TypeName: firstString(values, 6)}
	if label, found := firstVarint(values, 4); found {
		result.Label = labelName(label)
	}
	if kind, found := firstVarint(values, 5); found {
		result.Type = typeName(kind)
	}
	if index, found := firstVarint(values, 9); found {
		result.OneofIndex = &index
	}
	return result, true
}

func summarizeMessage(data []byte) (messageSummary, bool) {
	values, ok := fields(data)
	if !ok {
		return messageSummary{}, false
	}
	result := messageSummary{Name: firstString(values, 1)}
	if result.Name == "" {
		return messageSummary{}, false
	}
	for _, value := range values {
		if value.wire != 2 {
			continue
		}
		switch value.number {
		case 2:
			if field, valid := summarizeField(value.value); valid {
				result.Fields = append(result.Fields, field)
			}
		case 3:
			if message, valid := summarizeMessage(value.value); valid {
				result.Messages = append(result.Messages, message)
			}
		case 4:
			if enum, valid := summarizeEnum(value.value); valid {
				result.Enums = append(result.Enums, enum)
			}
		}
	}
	return result, true
}

func summarizeEnum(data []byte) (enumSummary, bool) {
	values, ok := fields(data)
	if !ok {
		return enumSummary{}, false
	}
	result := enumSummary{Name: firstString(values, 1)}
	if result.Name == "" {
		return enumSummary{}, false
	}
	for _, value := range values {
		if value.number != 2 || value.wire != 2 {
			continue
		}
		entry, valid := fields(value.value)
		if !valid {
			continue
		}
		name := firstString(entry, 1)
		number, found := firstVarint(entry, 2)
		if name != "" && found {
			result.Values = append(result.Values, enumValueSummary{Name: name, Number: number})
		}
	}
	return result, true
}

func summarizeMethod(data []byte) (methodSummary, bool) {
	values, ok := fields(data)
	if !ok {
		return methodSummary{}, false
	}
	result := methodSummary{
		Name:       firstString(values, 1),
		InputType:  firstString(values, 2),
		OutputType: firstString(values, 3),
	}
	if result.Name == "" || result.InputType == "" || result.OutputType == "" {
		return methodSummary{}, false
	}
	if value, found := firstVarint(values, 5); found {
		result.ClientStreaming = value != 0
	}
	if value, found := firstVarint(values, 6); found {
		result.ServerStreaming = value != 0
	}
	return result, true
}

func summarizeService(data []byte) (serviceSummary, bool) {
	values, ok := fields(data)
	if !ok {
		return serviceSummary{}, false
	}
	result := serviceSummary{Name: firstString(values, 1)}
	if result.Name == "" {
		return serviceSummary{}, false
	}
	for _, value := range values {
		if value.number == 2 && value.wire == 2 {
			if method, valid := summarizeMethod(value.value); valid {
				result.Methods = append(result.Methods, method)
			}
		}
	}
	return result, true
}

func summarizeFile(data []byte) (fileSummary, bool) {
	values, ok := fields(data)
	if !ok {
		return fileSummary{}, false
	}
	result := fileSummary{Name: firstString(values, 1), Package: firstString(values, 2)}
	if result.Name == "" || !strings.HasSuffix(result.Name, ".proto") {
		return fileSummary{}, false
	}
	for _, value := range values {
		switch value.number {
		case 3:
			if value.wire == 2 && utf8.Valid(value.value) {
				result.Dependencies = append(result.Dependencies, string(value.value))
			}
		case 4:
			if value.wire == 2 {
				if message, valid := summarizeMessage(value.value); valid {
					result.Messages = append(result.Messages, message)
				}
			}
		case 5:
			if value.wire == 2 {
				if enum, valid := summarizeEnum(value.value); valid {
					result.Enums = append(result.Enums, enum)
				}
			}
		case 6:
			if value.wire == 2 {
				if service, valid := summarizeService(value.value); valid {
					result.Services = append(result.Services, service)
				}
			}
		}
	}
	return result, true
}

func descriptorAt(data []byte, start int) ([]byte, bool) {
	offset := start
	seenName := false
	for offset < len(data) {
		field, next, ok := consumeField(data, offset)
		if !ok || next <= offset {
			return nil, false
		}
		if !seenName {
			if field.number != 1 || field.wire != 2 || !bytes.HasSuffix(field.value, []byte(".proto")) {
				return nil, false
			}
			seenName = true
		}
		offset = next
		if field.number == 12 && field.wire == 2 && (bytes.Equal(field.value, []byte("proto3")) || bytes.Equal(field.value, []byte("proto2"))) {
			return data[start:offset], true
		}
		if field.number > 14 {
			return nil, false
		}
	}
	return nil, false
}

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Fprintln(os.Stderr, "usage: describe-protos BINARY [FILTER]")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	filter := ""
	if len(os.Args) == 3 {
		filter = strings.ToLower(os.Args[2])
	}
	seen := map[string]bool{}
	var summaries []fileSummary
	for offset := 0; offset < len(data); offset++ {
		if data[offset] != 0x0a {
			continue
		}
		raw, ok := descriptorAt(data, offset)
		if !ok {
			continue
		}
		summary, ok := summarizeFile(raw)
		if !ok || seen[summary.Name] {
			continue
		}
		seen[summary.Name] = true
		encoded, _ := json.Marshal(summary)
		searchable := strings.ToLower(string(encoded))
		if filter != "" && !strings.Contains(searchable, filter) {
			continue
		}
		if filter == "" && len(summary.Services) == 0 {
			continue
		}
		summaries = append(summaries, summary)
	}
	sort.Slice(summaries, func(i, j int) bool { return summaries[i].Name < summaries[j].Name })
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	for _, summary := range summaries {
		if err := encoder.Encode(summary); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
