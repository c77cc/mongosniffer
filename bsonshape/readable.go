package bsonshape

import (
	"sort"
	"strconv"
	"strings"
	"unicode"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
)

type queryNode struct {
	kind     string
	text     string
	children []*queryNode
}

func readableFingerprint(doc bson.Raw, sequences []Sequence, cmd Command, limits Limits) (string, bool) {
	base := cmd.Name
	if cmd.Namespace != "" {
		base += " " + cmd.Namespace
	} else if cmd.Database != "" {
		base += " " + cmd.Database
	}
	var parts []string
	switch cmd.Name {
	case "find":
		parts = appendQueryParts(parts, doc, "filter", limits)
		parts = appendSort(parts, doc.Lookup("sort"))
		parts = appendOptional(parts, doc, "limit", "skip")
		parts = appendProjection(parts, doc.Lookup("projection"))
	case "count":
		parts = appendQueryParts(parts, doc, "query", limits)
		parts = appendOptional(parts, doc, "limit", "skip")
	case "distinct":
		parts = appendQueryParts(parts, doc, "query", limits)
		if key := stringValue(doc.Lookup("key")); key != "" {
			parts = append(parts, "field "+readableField(key))
		}
	case "findandmodify":
		parts = appendQueryParts(parts, doc, "query", limits)
		parts = appendSort(parts, doc.Lookup("sort"))
		parts = appendProjection(parts, doc.Lookup("fields"))
		if update := doc.Lookup("update"); update.Type != 0 {
			parts = append(parts, "update "+readableUpdate(update, limits))
		}
	case "aggregate":
		if pipeline := readablePipeline(doc.Lookup("pipeline"), limits); pipeline != "" {
			parts = append(parts, pipeline)
		}
	case "insert":
		if documents := readableInsertDocuments(doc, sequences); documents != "" {
			parts = append(parts, documents)
		}
	case "delete", "update":
		if requests := readableWriteRequests(cmd.Name, doc, sequences, limits); requests != "" {
			parts = append(parts, requests)
		}
	default:
		return boundedReadable(cmd.GroupKey, limits.MaxOutputBytes)
	}
	if len(parts) == 0 {
		return base, false
	}
	return boundedReadable(base+" "+strings.Join(parts, " "), limits.MaxOutputBytes)
}

func appendQueryParts(parts []string, doc bson.Raw, key string, limits Limits) []string {
	value := doc.Lookup(key)
	if value.Type != bsontype.EmbeddedDocument {
		return parts
	}
	node := queryDocument(value.Document(), "", limits)
	if node != nil {
		parts = append(parts, "where "+renderQuery(node, 0))
	}
	return parts
}

func appendSort(parts []string, value bson.RawValue) []string {
	if value.Type != bsontype.EmbeddedDocument {
		return parts
	}
	fields := documentFields(value.Document(), true)
	if len(fields) > 0 {
		parts = append(parts, "sort("+strings.Join(fields, ", ")+")")
	}
	return parts
}

func appendProjection(parts []string, value bson.RawValue) []string {
	if value.Type != bsontype.EmbeddedDocument {
		return parts
	}
	fields := documentFields(value.Document(), false)
	if len(fields) > 0 {
		parts = append(parts, "project("+strings.Join(fields, ", ")+")")
	}
	return parts
}

func appendOptional(parts []string, doc bson.Raw, keys ...string) []string {
	for _, key := range keys {
		if doc.Lookup(key).Type != 0 {
			parts = append(parts, key+" ?")
		}
	}
	return parts
}

func documentFields(doc bson.Raw, withValue bool) []string {
	elems, err := doc.Elements()
	if err != nil {
		return nil
	}
	fields := make([]string, 0, len(elems))
	for _, elem := range elems {
		if sensitiveKey(elem.Key()) {
			continue
		}
		field := readableField(elem.Key())
		if withValue {
			field += ": ?"
		}
		fields = append(fields, field)
	}
	return fields
}

func readablePipeline(value bson.RawValue, limits Limits) string {
	if value.Type != bsontype.Array {
		return ""
	}
	values, err := value.Array().Values()
	if err != nil {
		return ""
	}
	stages := make([]string, 0, len(values))
	for _, stage := range values {
		if stage.Type != bsontype.EmbeddedDocument {
			stages = append(stages, "?")
			continue
		}
		elems, _ := stage.Document().Elements()
		if len(elems) != 1 {
			stages = append(stages, readableValueShape(stage, limits))
			continue
		}
		name, stageValue := elems[0].Key(), elems[0].Value()
		switch name {
		case "$match":
			if stageValue.Type == bsontype.EmbeddedDocument {
				stages = append(stages, "match("+renderQuery(queryDocument(stageValue.Document(), "", limits), 0)+")")
			} else {
				stages = append(stages, "match(?)")
			}
		case "$sort":
			if stageValue.Type == bsontype.EmbeddedDocument {
				stages = append(stages, "sort("+strings.Join(documentFields(stageValue.Document(), true), ", ")+")")
			} else {
				stages = append(stages, "sort(?)")
			}
		case "$project":
			if stageValue.Type == bsontype.EmbeddedDocument {
				stages = append(stages, "project("+strings.Join(documentFields(stageValue.Document(), false), ", ")+")")
			} else {
				stages = append(stages, "project(?)")
			}
		case "$limit", "$skip", "$count", "$unwind":
			stages = append(stages, strings.TrimPrefix(name, "$")+" ?")
		default:
			stages = append(stages, name+" "+readableValueShape(stageValue, limits))
		}
	}
	return "pipeline[" + strings.Join(stages, ", ") + "]"
}

func readableWriteRequests(command string, doc bson.Raw, sequences []Sequence, limits Limits) string {
	identifier := command + "s"
	var documents [][]byte
	for _, sequence := range sequences {
		if strings.EqualFold(sequence.Identifier, identifier) {
			documents = append(documents, sequence.Documents...)
		}
	}
	if len(documents) == 0 {
		value := doc.Lookup(identifier)
		if value.Type == bsontype.Array {
			values, _ := value.Array().Values()
			for _, item := range values {
				if item.Type == bsontype.EmbeddedDocument {
					documents = append(documents, []byte(item.Document()))
				}
			}
		}
	}
	if len(documents) == 0 {
		return ""
	}
	seen := make(map[string]struct{})
	requests := make([]string, 0, len(documents))
	for _, raw := range documents {
		request := bson.Raw(raw)
		if validateRaw(request) != nil {
			continue
		}
		var parts []string
		query := request.Lookup("q")
		if query.Type == bsontype.EmbeddedDocument {
			parts = append(parts, "where "+renderQuery(queryDocument(query.Document(), "", limits), 0))
		}
		if command == "update" {
			if update := request.Lookup("u"); update.Type != 0 {
				parts = append(parts, "update "+readableUpdate(update, limits))
			}
		}
		if request.Lookup("limit").Type != 0 {
			parts = append(parts, "limit ?")
		}
		value := strings.Join(parts, " ")
		if _, exists := seen[value]; !exists {
			seen[value] = struct{}{}
			requests = append(requests, value)
		}
	}
	sort.Strings(requests)
	if len(requests) == 1 {
		return requests[0]
	}
	return "requests[" + strings.Join(requests, "; ") + "]"
}

func readableInsertDocuments(doc bson.Raw, sequences []Sequence) string {
	var documents []bson.Raw
	for _, sequence := range sequences {
		if strings.EqualFold(sequence.Identifier, "documents") {
			for _, raw := range sequence.Documents {
				documents = append(documents, bson.Raw(raw))
			}
		}
	}
	if len(documents) == 0 {
		value := doc.Lookup("documents")
		if value.Type == bsontype.Array {
			values, _ := value.Array().Values()
			for _, item := range values {
				if item.Type == bsontype.EmbeddedDocument {
					documents = append(documents, item.Document())
				}
			}
		}
	}
	shapes := make(map[string]struct{})
	for _, document := range documents {
		fields := documentFields(document, false)
		if len(fields) > 0 {
			shapes["("+strings.Join(fields, ", ")+")"] = struct{}{}
		}
	}
	values := make([]string, 0, len(shapes))
	for shape := range shapes {
		values = append(values, shape)
	}
	sort.Strings(values)
	if len(values) == 0 {
		return ""
	}
	if len(values) == 1 {
		return "documents" + values[0]
	}
	return "documents[" + strings.Join(values, ", ") + "]"
}

func readableUpdate(value bson.RawValue, limits Limits) string {
	if value.Type != bsontype.EmbeddedDocument {
		return "?"
	}
	elems, err := value.Document().Elements()
	if err != nil || len(elems) == 0 {
		return "{}"
	}
	for _, elem := range elems {
		if !strings.HasPrefix(elem.Key(), "$") {
			return "replace(" + strings.Join(documentFields(value.Document(), false), ", ") + ")"
		}
	}
	parts := make([]string, 0, len(elems))
	for _, elem := range elems {
		if elem.Value().Type == bsontype.EmbeddedDocument {
			parts = append(parts, elem.Key()+"("+strings.Join(documentFields(elem.Value().Document(), false), ", ")+")")
		} else {
			parts = append(parts, elem.Key()+"(?)")
		}
	}
	result, _ := boundedReadable(strings.Join(parts, ", "), limits.MaxOutputBytes)
	return result
}

type queryBudget struct {
	remaining int
	maxDepth  int
}

func queryDocument(doc bson.Raw, prefix string, limits Limits) *queryNode {
	budget := &queryBudget{remaining: limits.MaxElements, maxDepth: limits.MaxDepth}
	return queryDocumentWithBudget(doc, prefix, 0, budget)
}

func queryDocumentWithBudget(doc bson.Raw, prefix string, depth int, budget *queryBudget) *queryNode {
	if depth >= budget.maxDepth {
		return &queryNode{kind: "predicate", text: "…[depth]"}
	}
	elems, err := doc.Elements()
	if err != nil {
		return &queryNode{kind: "predicate", text: "…[invalid]"}
	}
	children := make([]*queryNode, 0, len(elems))
	for _, elem := range elems {
		key := elem.Key()
		if sensitiveKey(key) {
			continue
		}
		if budget.remaining <= 0 {
			children = append(children, &queryNode{kind: "predicate", text: "…[clauses]"})
			break
		}
		budget.remaining--
		if key == "$and" || key == "$or" || key == "$nor" {
			children = append(children, queryLogical(strings.TrimPrefix(key, "$"), elem.Value(), depth+1, budget))
			continue
		}
		if strings.HasPrefix(key, "$") {
			children = append(children, &queryNode{kind: "predicate", text: key + " " + queryPlaceholder(elem.Value())})
			continue
		}
		field := key
		if prefix != "" {
			field = prefix + "." + key
		}
		children = append(children, queryField(field, elem.Value(), depth+1, budget))
	}
	return logicalNode("and", children)
}

func queryLogical(kind string, value bson.RawValue, depth int, budget *queryBudget) *queryNode {
	if value.Type != bsontype.Array {
		return &queryNode{kind: "predicate", text: "$" + kind + " ?"}
	}
	values, err := value.Array().Values()
	if err != nil {
		return &queryNode{kind: "predicate", text: "$" + kind + " ?"}
	}
	children := make([]*queryNode, 0, len(values))
	for _, item := range values {
		if budget.remaining <= 0 {
			children = append(children, &queryNode{kind: "predicate", text: "…[clauses]"})
			break
		}
		if item.Type == bsontype.EmbeddedDocument {
			children = append(children, queryDocumentWithBudget(item.Document(), "", depth+1, budget))
		} else {
			children = append(children, &queryNode{kind: "predicate", text: "?"})
		}
	}
	return logicalNode(kind, children)
}

func queryField(field string, value bson.RawValue, depth int, budget *queryBudget) *queryNode {
	name := readableField(field)
	if value.Type != bsontype.EmbeddedDocument {
		return &queryNode{kind: "predicate", text: name + " = " + queryPlaceholder(value)}
	}
	elems, err := value.Document().Elements()
	if err != nil || len(elems) == 0 {
		return &queryNode{kind: "predicate", text: name + " = {}"}
	}
	hasOperator := false
	for _, elem := range elems {
		hasOperator = hasOperator || strings.HasPrefix(elem.Key(), "$")
	}
	if !hasOperator {
		return &queryNode{kind: "predicate", text: name + " = " + readableDocumentShape(value.Document())}
	}
	children := make([]*queryNode, 0, len(elems))
	for _, elem := range elems {
		if budget.remaining <= 0 {
			children = append(children, &queryNode{kind: "predicate", text: "…[clauses]"})
			break
		}
		budget.remaining--
		op, operand := elem.Key(), elem.Value()
		switch op {
		case "$not":
			if operand.Type == bsontype.EmbeddedDocument {
				children = append(children, &queryNode{kind: "not", children: []*queryNode{queryField(field, operand, depth+1, budget)}})
			} else {
				children = append(children, &queryNode{kind: "predicate", text: name + " not ?"})
			}
		case "$elemMatch":
			if operand.Type == bsontype.EmbeddedDocument {
				children = append(children, &queryNode{kind: "predicate", text: name + " elemMatch (" + renderQuery(queryDocumentWithBudget(operand.Document(), "", depth+1, budget), 0) + ")"})
			} else {
				children = append(children, &queryNode{kind: "predicate", text: name + " elemMatch ?"})
			}
		default:
			children = append(children, &queryNode{kind: "predicate", text: name + " " + readableOperator(op) + " " + queryPlaceholderForOperator(op, operand)})
		}
	}
	return logicalNode("and", children)
}

func logicalNode(kind string, children []*queryNode) *queryNode {
	flat := make([]*queryNode, 0, len(children))
	for _, child := range children {
		if child == nil {
			continue
		}
		if child.kind == kind && (kind == "and" || kind == "or") {
			flat = append(flat, child.children...)
		} else {
			flat = append(flat, child)
		}
	}
	if len(flat) == 0 {
		return nil
	}
	if len(flat) == 1 && kind == "and" {
		return flat[0]
	}
	if kind == "and" || kind == "or" || kind == "nor" {
		sort.Slice(flat, func(i, j int) bool { return renderQuery(flat[i], 0) < renderQuery(flat[j], 0) })
	}
	return &queryNode{kind: kind, children: flat}
}

func renderQuery(node *queryNode, parentPrecedence int) string {
	if node == nil {
		return "{}"
	}
	if node.kind == "predicate" {
		return node.text
	}
	if node.kind == "not" {
		if len(node.children) == 0 {
			return "not (?)"
		}
		return "not (" + renderQuery(node.children[0], 0) + ")"
	}
	separator, precedence := " and ", 2
	if node.kind == "or" {
		separator, precedence = " or ", 1
	}
	if node.kind == "nor" {
		values := make([]string, 0, len(node.children))
		for _, child := range node.children {
			values = append(values, renderQuery(child, 0))
		}
		return "nor(" + strings.Join(values, ", ") + ")"
	}
	values := make([]string, 0, len(node.children))
	for _, child := range node.children {
		values = append(values, renderQuery(child, precedence))
	}
	result := strings.Join(values, separator)
	if precedence < parentPrecedence {
		return "(" + result + ")"
	}
	return result
}

func readableOperator(operator string) string {
	switch operator {
	case "$eq":
		return "="
	case "$ne":
		return "!="
	case "$gt":
		return ">"
	case "$gte":
		return ">="
	case "$lt":
		return "<"
	case "$lte":
		return "<="
	case "$in":
		return "in"
	case "$nin":
		return "not in"
	case "$all":
		return "all"
	case "$exists":
		return "exists"
	case "$regex":
		return "regex"
	case "$size":
		return "size"
	case "$type":
		return "type"
	default:
		return operator
	}
}

func queryPlaceholderForOperator(operator string, value bson.RawValue) string {
	if operator == "$in" || operator == "$nin" || operator == "$all" || value.Type == bsontype.Array {
		return "[?]"
	}
	if value.Type == bsontype.EmbeddedDocument {
		return readableDocumentShape(value.Document())
	}
	return "?"
}

func queryPlaceholder(value bson.RawValue) string {
	return queryPlaceholderDepth(value, 0)
}

func queryPlaceholderDepth(value bson.RawValue, depth int) string {
	if value.Type == bsontype.Array {
		return "[?]"
	}
	if value.Type == bsontype.EmbeddedDocument {
		return readableDocumentShapeDepth(value.Document(), depth+1)
	}
	return "?"
}

func readableDocumentShape(doc bson.Raw) string {
	return readableDocumentShapeDepth(doc, 0)
}

func readableDocumentShapeDepth(doc bson.Raw, depth int) string {
	if depth >= DefaultLimits().MaxDepth {
		return "{…[depth]}"
	}
	elems, err := doc.Elements()
	if err != nil {
		return "{?}"
	}
	parts := make([]string, 0, len(elems))
	for _, elem := range elems {
		if sensitiveKey(elem.Key()) {
			continue
		}
		parts = append(parts, readableField(elem.Key())+": "+queryPlaceholderDepth(elem.Value(), depth+1))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func readableValueShape(value bson.RawValue, limits Limits) string {
	return valueShape(value, 0, "", limits)
}

func readableField(field string) string {
	if field == "" {
		return strconv.Quote(field)
	}
	for _, r := range field {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '.' || r == '$') {
			return strconv.Quote(field)
		}
	}
	return field
}

func boundedReadable(value string, maximum int) (string, bool) {
	if maximum <= 0 || len(value) <= maximum {
		return value, false
	}
	token := " …[truncated]"
	if maximum <= len(token) {
		return token[:maximum], true
	}
	return value[:maximum-len(token)] + token, true
}
