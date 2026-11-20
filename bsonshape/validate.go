package bsonshape

import (
	"encoding/binary"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
)

func validateRaw(doc bson.Raw) (err error) {
	if len(doc) < 5 {
		return fmt.Errorf("BSON document is shorter than 5 bytes")
	}
	declared := int64(int32(binary.LittleEndian.Uint32(doc[:4])))
	if declared != int64(len(doc)) {
		return fmt.Errorf("BSON document length is %d, got %d bytes", declared, len(doc))
	}
	if doc[len(doc)-1] != 0 {
		return fmt.Errorf("BSON document is missing its terminator")
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("invalid BSON document: %v", recovered)
		}
	}()
	return doc.Validate()
}
