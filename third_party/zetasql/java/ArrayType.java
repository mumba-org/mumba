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

import com.google.common.base.Preconditions;
import com.google.zetasql.ZetaSQLOptions.ProductMode;
import com.google.zetasql.ZetaSQLType.ArrayTypeProto;
import com.google.zetasql.ZetaSQLType.TypeKind;
import com.google.zetasql.ZetaSQLType.TypeProto;
import java.util.Objects;

/**
 * An array type.
 * Arrays of arrays are not supported.
 */
public class ArrayType extends Type {
  static boolean equalsImpl(ArrayType type1, ArrayType type2, boolean equivalent) {
    return type1.elementType.equalsInternal(type2.elementType, equivalent);
  }

  private final Type elementType;

  /** Private constructor, instances must be created with {@link TypeFactory} */
  ArrayType(Type elementType) {
    super(TypeKind.TYPE_ARRAY);
    Preconditions.checkArgument(elementType.getKind() != TypeKind.TYPE_ARRAY);
    this.elementType = elementType;
  }

  public Type getElementType() {
    return elementType;
  }

  @Override
  public void serialize(
      TypeProto.Builder typeProtoBuilder,
      FileDescriptorSetsBuilder fileDescriptorSetsBuilder) {
    typeProtoBuilder.setTypeKind(getKind());
    ArrayTypeProto.Builder array = typeProtoBuilder.getArrayTypeBuilder();
    elementType.serialize(array.getElementTypeBuilder(), fileDescriptorSetsBuilder);
  }

  @Override
  public int hashCode() {
    return Objects.hash(elementType, getKind());
  }

  @Override
  public String typeName(ProductMode productMode) {
    return String.format("ARRAY<%s>", elementType.typeName(productMode));
  }

  @Override
  public String debugString(boolean details) {
    return String.format("ARRAY<%s>", elementType.debugString(details));
  }

  @Override
  public ArrayType asArray() {
    return this;
  }
}
