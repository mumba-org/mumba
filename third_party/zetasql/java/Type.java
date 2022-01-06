/*
 * Copyright 2019 ZetaSQL Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package com.google.zetasql;

import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.DescriptorProtos.FileDescriptorSet;
import com.google.zetasql.ZetaSQLOptions.ProductMode;
import com.google.zetasql.ZetaSQLType.TypeKind;
import com.google.zetasql.ZetaSQLType.TypeProto;
import java.io.Serializable;

/**
 * In-memory representation of a ZetaSQL type. See (broken link) for more information on the
 * type system.
 *
 * <p>Types can only created by a TypeFactory.
 */
@Immutable
public abstract class Type implements Serializable {
  // The valid date range is [ 0001-01-01, 9999-12-31 ].
  public static final int DATE_MIN = -719162;
  public static final int DATE_MAX = 2932896;

  // The valid timestamp range for timestamps is:
  //  [ 0001-01-01 00:00:00 UTC, 9999-12-31 23:59:59.999999 UTC ]
  public static final long TIMESTAMP_MICROS_MIN = -62135596800L * 1000000;
  public static final long TIMESTAMP_MICROS_MAX = 253402300800L * 1000000 - 1;

  // The order should be the same as the order in zetasql.TypeKind
  static final String[] TYPE_KIND_NAMES = {
    "UNKNOWN", // Not a valid type.
    "INT32",
    "INT64",
    "UINT32",
    "UINT64",
    "BOOL",
    "FLOAT",
    "DOUBLE",
    "STRING",
    "BYTES",
    "DATE",
    "TIMESTAMP_SECONDS",
    "TIMESTAMP_MILLIS",
    "TIMESTAMP_MICROS",
    "", // Used to be TIMESTAMP_NANOS, removed.
    "ENUM",
    "ARRAY",
    "STRUCT",
    "PROTO",
    "TIMESTAMP",
    "TIME",
    "DATETIME",
    "GEOGRAPHY",
    "NUMERIC",
  };

  /**
   * Returns {@code true} if the given {@code date} value is within valid range.
   */
  public static boolean isValidDate(int date) {
    return date >= DATE_MIN && date <= DATE_MAX;
  }

  /**
   * Returns {@code true} if the given {@code timestamp} value is within valid
   * range.
   */
  public static boolean isValidTimestampUnixMicros(long timestamp) {
    return timestamp >= TIMESTAMP_MICROS_MIN && timestamp <= TIMESTAMP_MICROS_MAX;
  }

  /**
   * Returns {@code true} if the given {@code timestamp} value is within valid
   * range.
   */
  public static boolean isValidTimestamp(com.google.protobuf.Timestamp timestamp) {
    return timestamp.getSeconds() >= TIMESTAMP_MICROS_MIN / 1000000
        && timestamp.getSeconds() < (TIMESTAMP_MICROS_MAX + 1) / 1000000;
  }

  private final TypeKind kind;

  Type(TypeKind kind) {
    this.kind = kind;
  }

  /** Returns TypeKind of this type. */
  public TypeKind getKind() {
    return kind;
  }

  public boolean isInt32() {
    return kind == TypeKind.TYPE_INT32;
  }

  public boolean isInt64() {
    return kind == TypeKind.TYPE_INT64;
  }

  public boolean isUint32() {
    return kind == TypeKind.TYPE_UINT32;
  }

  public boolean isUint64() {
    return kind == TypeKind.TYPE_UINT64;
  }

  public boolean isBool() {
    return kind == TypeKind.TYPE_BOOL;
  }

  public boolean isFloat() {
    return kind == TypeKind.TYPE_FLOAT;
  }

  public boolean isDouble() {
    return kind == TypeKind.TYPE_DOUBLE;
  }

  public boolean isNumeric() {
    return kind == TypeKind.TYPE_NUMERIC;
  }

  public boolean isString() {
    return kind == TypeKind.TYPE_STRING;
  }

  public boolean isBytes() {
    return kind == TypeKind.TYPE_BYTES;
  }

  public boolean isDate() {
    return kind == TypeKind.TYPE_DATE;
  }

  public boolean isTimestamp() {
    return kind == TypeKind.TYPE_TIMESTAMP;
  }

  public boolean isDatetime() {
    return kind == TypeKind.TYPE_DATETIME;
  }

  public boolean isTime() {
    return kind == TypeKind.TYPE_TIME;
  }

  public boolean isGeography() {
    return kind == TypeKind.TYPE_GEOGRAPHY;
  }

  public boolean isEnum() {
    return kind == TypeKind.TYPE_ENUM;
  }

  public boolean isArray() {
    return kind == TypeKind.TYPE_ARRAY;
  }

  public boolean isStruct() {
    return kind == TypeKind.TYPE_STRUCT;
  }

  public boolean isProto() {
    return kind == TypeKind.TYPE_PROTO;
  }

  public boolean isStructOrProto() {
    return isStruct() || isProto();
  }

  public boolean isFloatingPoint() {
    return isFloat() || isDouble();
  }

  public boolean isNumerical() {
    return isInt32()
           || isInt64()
           || isUint32()
           || isUint64()
           || isFloat()
           || isDouble()
           || kind == TypeKind.TYPE_NUMERIC;
  }

  public boolean isInteger() {
    return isInt32() || isInt64() || isUint32() || isUint64();
  }

  public boolean isSignedInteger() {
    return isInt32() || isInt64();
  }

  public boolean isUnsignedInteger() {
    return isUint32() || isUint64();
  }

  /**
   * Simple types are those that can be represented with just a TypeKind,
   * with no parameters.
   *
   * @return Whether this type is a simple type.
   */
  public boolean isSimpleType() {
    return TypeFactory.isSimpleType(kind);
  }

  /**
   * Serialize this type into self-contained protobuf.
   *
   * @return The serialized protobuf.
   */
  public TypeProto serialize() {
    TypeProto.Builder typeProtoBuilder = TypeProto.newBuilder();
    FileDescriptorSetsBuilder fileDescriptorSetsBuilder = new FileDescriptorSetsBuilder();
    serialize(typeProtoBuilder, fileDescriptorSetsBuilder);
    for (FileDescriptorSet set : fileDescriptorSetsBuilder.build()) {
      typeProtoBuilder.addFileDescriptorSet(set);
    }
    return typeProtoBuilder.build();
  }

  /**
   * Serialize the this type to a non-self-contained TypeProto and an array of
   * FileDescriptorSet using the given builders. To deserialize the Type, the
   * FileDescriptorSet array must be provided together with TypeProto.
   *
   * <p>To efficiently serialize multiple Types, one can use this method with
   * the same FileDescriptorSetsBuilder, the built List&lt;FileDescriptorSet&rt;
   * will then include all FileDescriptors that are required to deserialize all
   * the Types. This effectively avoids duplicates in multiple self-contained
   * TypeProtos.
   *
   * @param typeProtoBuilder
   * @param fileDescriptorSetsBuilder
   */
  public abstract void serialize(
      TypeProto.Builder typeProtoBuilder,
      FileDescriptorSetsBuilder fileDescriptorSetsBuilder);

  /**
   * Compare types for equivalence.  Equivalent types can be used
   * interchangeably in a query, but casts will always be added to convert
   * from one to the other.
   *
   * <p> This differs from Equals in that it treats Enums and Protos as
   * equivalent if their full_name() is equal.  Different versions of the
   * same proto or enum are equivalent in a query, but CASTs will be added
   * to do the conversion.
   *
   * <p> Structs with different field names are not considered Equivalent.
   *
   * @param other
   * @return Whether this type is equivalent to the given other type.
   */
  public boolean equivalent(Type other) {
    return equalsInternal(other, true  /* equivalent */);
  }

  /**
   * Compares types for equality. Equal types can be used interchangeably
   * without any casting.
   *
   * <p>This compares structurally inside structs and arrays.
   * For protos and enums, this does proto descriptor pointer comparison only.
   * Two versions of identical descriptors (from different DescriptorPools)
   * will not be considered equal.
   *
   * @param other
   * @return Whether this type is equal to the given other type.
   */
  @Override
  public boolean equals(Object other) {
    return (other instanceof Type) && equalsInternal((Type) other, false  /* equivalent */);
  }

  @Override
  public abstract int hashCode();

  /**
   * Returns the SQL name for this type, which will be reparseable as part
   * of a query.  For proto-based types, this just returns the type name, which
   * does not easily distinguish PROTOs from ENUMs.
   *
   * @param productMode
   * @return The SQL name for this type.
   */
  public abstract String typeName(ProductMode productMode);

  public final String typeName() {
    return typeName(ProductMode.PRODUCT_INTERNAL);
  }

  /**
   * Returns the full description of the type.  For proto-based types, this will
   * return {@code PROTO<name>} or {@code ENUM<name>}, which are not valid to parse as SQL.
   * If {@code details} is true, then the description includes full proto descriptors.
   *
   * @param details
   * @return Full description of the type.
   */
  public abstract String debugString(boolean details);

  /**
   * Returns the full description of the type.  For proto-based types, this will
   * return {@code PROTO<name>} or {@code ENUM<name>}, which are not valid to parse as SQL.
   * Tht description does NOT include full proto descriptors.
   * @return Full description of the type.
   */
  public String debugString() {
    return debugString(false);
  }

  @Override
  public String toString() {
    return debugString(false);
  }

  /** Returns {@code this} cast to ArrayType or null for other types. */
  public ArrayType asArray() {
    return null;
  }

  /** Returns {@code this} cast to EnumType or null for other types. */
  public EnumType asEnum() {
    return null;
  }

  /** Returns {@code this} cast to ProtoType or null for other types. */
  public ProtoType asProto() {
    return null;
  }

  /** Returns {@code this} cast to StructType or null for other types. */
  public StructType asStruct() {
    return null;
  }

  @SuppressWarnings("ReferenceEquality")
  protected boolean equalsInternal(Type other, boolean equivalent) {
    if (other == this) {
      return true;
    }

    if (other == null) {
      return false;
    }

    if (kind != other.kind) {
      return false;
    }

    if (isSimpleType()) {
      return true;
    }

    switch (kind) {
      case TYPE_ENUM:
        return EnumType.equalsImpl(this.asEnum(), other.asEnum(), equivalent);
      case TYPE_ARRAY:
        return ArrayType.equalsImpl(this.asArray(), other.asArray(), equivalent);
      case TYPE_STRUCT:
        return StructType.equalsImpl(this.asStruct(), other.asStruct(), equivalent);
      case TYPE_PROTO:
        return ProtoType.equalsImpl(this.asProto(), other.asProto(), equivalent);
      default:
        throw new IllegalArgumentException("Shouldn't happen: unsupported type " + other);
    }
  }
}
