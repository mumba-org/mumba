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
import com.google.zetasql.ZetaSQLParser.ParseResumeLocationProto;
import com.google.zetasql.LocalService.RegisterResponse;
import com.google.zetasql.LocalService.UnregisterRequest;
import io.grpc.StatusRuntimeException;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * The ParseResumeLocation class stores the parser input and a location, and is used as a restart
 * token in repeated calls to operations that parse multiple items from one input string. Each
 * successive call updates this location object so the next call knows where to start.
 */
public class ParseResumeLocation {
  private static final Logger logger = Logger.getLogger(ParseResumeLocation.class.getName());

  private String filename;
  private String input;
  private int bytePosition = 0;
  private boolean allowResume = true;

  private boolean registered = false;
  private long registeredId = -1;

  /**
   * The constructor of ParseResumeLocation. Initially the value of bytePosition is zero and the
   * allowResume is true.
   */
  public ParseResumeLocation(String filename, String input) {
    setFilename(filename);
    setInput(input);
  }
  public ParseResumeLocation(String input) {
    setFilename("");
    setInput(input);
  }

  ParseResumeLocation(ParseResumeLocationProto proto) {
    filename = proto.getFilename();
    input = proto.getInput();
    bytePosition = proto.getBytePosition();
    allowResume = proto.getAllowResume();
  }

  ParseResumeLocationProto serialize() {
    ParseResumeLocationProto.Builder protoBuilder = ParseResumeLocationProto.newBuilder();
    protoBuilder.setBytePosition(bytePosition);
    protoBuilder.setFilename(filename);
    protoBuilder.setInput(input);
    protoBuilder.setAllowResume(allowResume);
    ParseResumeLocationProto ret = protoBuilder.build();
    return ret;
  }

  public AutoUnregister register() {
    Preconditions.checkState(!registered);

    try {
      RegisterResponse resp = Client.getStub().registerParseResumeLocation(serialize());
      registeredId = resp.getRegisteredId();
    } catch (StatusRuntimeException e) {
      throw new SqlException(e);
    }

    registered = true;
    return new AutoUnregister();
  }

  public void unregister() {
    Preconditions.checkState(registered);
    try {
      Client.getStub()
          .unregisterParseResumeLocation(
              UnregisterRequest.newBuilder().setRegisteredId(registeredId).build());
    } catch (StatusRuntimeException e) {
      // Maybe caused by double unregistering (in race conditions) or RPC
      // failure. The latter may cause leak but it's likely due to more serious
      // problems and there is no good way to recover. Just log and ignore.
      logger.severe("Failed to unregister parse resume location: " + e.getMessage());
    } finally {
      registered = false;
      registeredId = -1;
    }
  }

  public boolean isRegistered() {
    return registered;
  }

  long getRegisteredId() {
    Preconditions.checkState(registered);
    return registeredId;
  }

  /**
   * AutoCloseable implementation that unregisters the ParseResumeLocation automatically when used
   * in try-with-resources.
   */
  public class AutoUnregister implements AutoCloseable {
    @Override
    public void close() {
      unregister();
    }
  }

  /** Get the filename associated with the parser input. */
  public String getFilename() {
    return filename;
  }

  /** Get the parser input. */
  public String getInput() {
    return input;
  }

  /** Get a position which indicates the beginning position of the not token input. */
  public int getBytePosition() {
    return bytePosition;
  }

  public boolean getAllowResume() {
    return allowResume;
  }

  public void setFilename(String filename) {
    Preconditions.checkState(!registered);
    this.filename = filename;
  }

  public void setInput(String input) {
    Preconditions.checkState(!registered);
    this.input = input;
  }

  /** Set the position which indicates the beginning position of the not token input. */
  public void setBytePosition(int bytePosition) {
    this.bytePosition = bytePosition;
  }

  public void disallowResume() {
    Preconditions.checkState(!registered);
    this.allowResume = false;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    }
    if (!(other instanceof ParseResumeLocation)) {
      return false;
    }
    ParseResumeLocation theOther = (ParseResumeLocation) other;
    if (filename == null) {
      if (theOther.filename != null) {
        return false;
      }
    } else if (!filename.equals(theOther.filename)) {
      return false;
    }
    if (input == null) {
      if (theOther.input != null) {
        return false;
      }
    } else if (!input.equals(theOther.input)) {
      return false;
    }
    return bytePosition == theOther.bytePosition && allowResume == theOther.allowResume;
  }

  @Override
  public int hashCode() {
    return Objects.hash(filename, input, bytePosition, allowResume);
  }
}
