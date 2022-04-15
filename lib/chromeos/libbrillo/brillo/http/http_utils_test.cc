// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <numeric>
#include <string>
#include <vector>

#include <base/bind.h>
#include <base/values.h>
#include <brillo/http/http_transport_fake.h>
#include <brillo/http/http_utils.h>
#include <brillo/mime_utils.h>
#include <brillo/strings/string_utils.h>
#include <brillo/url_utils.h>
#include <gtest/gtest.h>

namespace brillo {
namespace http {

static const char kFakeUrl[] = "http://localhost";
static const char kEchoUrl[] = "http://localhost/echo";
static const char kMethodEchoUrl[] = "http://localhost/echo/method";

///////////////////// Generic helper request handlers /////////////////////////
// Returns the request data back with the same content type.
static void EchoDataHandler(const fake::ServerRequest& request,
                            fake::ServerResponse* response) {
  response->Reply(status_code::Ok, request.GetData(),
                  request.GetHeader(request_header::kContentType));
}

// Returns the request method as a plain text response.
static void EchoMethodHandler(const fake::ServerRequest& request,
                              fake::ServerResponse* response) {
  response->ReplyText(status_code::Ok, request.GetMethod(),
                      brillo::mime::text::kPlain);
}

///////////////////////////////////////////////////////////////////////////////
TEST(HttpUtils, SendRequest_BinaryData) {
  std::shared_ptr<fake::Transport> transport(new fake::Transport);
  transport->AddHandler(kEchoUrl, request_type::kPost,
                        base::Bind(EchoDataHandler));

  // Test binary data round-tripping.
  std::vector<uint8_t> custom_data{0xFF, 0x00, 0x80, 0x40, 0xC0, 0x7F};
  auto response = http::SendRequestAndBlock(
      request_type::kPost, kEchoUrl, custom_data.data(), custom_data.size(),
      brillo::mime::application::kOctet_stream, {}, transport, nullptr);
  EXPECT_TRUE(response->IsSuccessful());
  EXPECT_EQ(brillo::mime::application::kOctet_stream,
            response->GetContentType());
  EXPECT_EQ(custom_data, response->ExtractData());
}

TEST(HttpUtils, SendRequestAsync_BinaryData) {
  std::shared_ptr<fake::Transport> transport(new fake::Transport);
  transport->AddHandler(kEchoUrl, request_type::kPost,
                        base::Bind(EchoDataHandler));

  // Test binary data round-tripping.
  std::vector<uint8_t> custom_data{0xFF, 0x00, 0x80, 0x40, 0xC0, 0x7F};
  auto success_callback = base::Bind(
      [](const std::vector<uint8_t>& custom_data, RequestID /* id */,
         std::unique_ptr<http::Response> response) {
        EXPECT_TRUE(response->IsSuccessful());
        EXPECT_EQ(brillo::mime::application::kOctet_stream,
                  response->GetContentType());
        EXPECT_EQ(custom_data, response->ExtractData());
      },
      custom_data);
  auto error_callback = [](RequestID /* id */, const Error* /* error */) {
    FAIL() << "This callback shouldn't have been called";
  };
  http::SendRequest(request_type::kPost, kEchoUrl, custom_data.data(),
                    custom_data.size(),
                    brillo::mime::application::kOctet_stream, {}, transport,
                    success_callback, base::Bind(error_callback));
}

TEST(HttpUtils, SendRequest_Post) {
  std::shared_ptr<fake::Transport> transport(new fake::Transport);
  transport->AddHandler(kMethodEchoUrl, "*", base::Bind(EchoMethodHandler));

  // Test binary data round-tripping.
  std::vector<uint8_t> custom_data{0xFF, 0x00, 0x80, 0x40, 0xC0, 0x7F};

  // Check the correct HTTP method used.
  auto response = http::SendRequestAndBlock(
      request_type::kPost, kMethodEchoUrl, custom_data.data(),
      custom_data.size(), brillo::mime::application::kOctet_stream, {},
      transport, nullptr);
  EXPECT_TRUE(response->IsSuccessful());
  EXPECT_EQ(brillo::mime::text::kPlain, response->GetContentType());
  EXPECT_EQ(request_type::kPost, response->ExtractDataAsString());
}

TEST(HttpUtils, SendRequest_Get) {
  std::shared_ptr<fake::Transport> transport(new fake::Transport);
  transport->AddHandler(kMethodEchoUrl, "*", base::Bind(EchoMethodHandler));

  auto response =
      http::SendRequestAndBlock(request_type::kGet, kMethodEchoUrl, nullptr, 0,
                                std::string{}, {}, transport, nullptr);
  EXPECT_TRUE(response->IsSuccessful());
  EXPECT_EQ(brillo::mime::text::kPlain, response->GetContentType());
  EXPECT_EQ(request_type::kGet, response->ExtractDataAsString());
}

TEST(HttpUtils, SendRequest_Put) {
  std::shared_ptr<fake::Transport> transport(new fake::Transport);
  transport->AddHandler(kMethodEchoUrl, "*", base::Bind(EchoMethodHandler));

  auto response =
      http::SendRequestAndBlock(request_type::kPut, kMethodEchoUrl, nullptr, 0,
                                std::string{}, {}, transport, nullptr);
  EXPECT_TRUE(response->IsSuccessful());
  EXPECT_EQ(brillo::mime::text::kPlain, response->GetContentType());
  EXPECT_EQ(request_type::kPut, response->ExtractDataAsString());
}

TEST(HttpUtils, SendRequest_NotFound) {
  std::shared_ptr<fake::Transport> transport(new fake::Transport);
  // Test failed response (URL not found).
  auto response = http::SendRequestWithNoDataAndBlock(
      request_type::kGet, "http://blah.com", {}, transport, nullptr);
  EXPECT_FALSE(response->IsSuccessful());
  EXPECT_EQ(status_code::NotFound, response->GetStatusCode());
}

TEST(HttpUtils, SendRequestAsync_NotFound) {
  std::shared_ptr<fake::Transport> transport(new fake::Transport);
  // Test failed response (URL not found).
  auto success_callback = [](RequestID /* request_id */,
                             std::unique_ptr<http::Response> response) {
    EXPECT_FALSE(response->IsSuccessful());
    EXPECT_EQ(status_code::NotFound, response->GetStatusCode());
  };
  auto error_callback = [](RequestID /* request_id */,
                           const Error* /* error */) {
    FAIL() << "This callback shouldn't have been called";
  };
  http::SendRequestWithNoData(request_type::kGet, "http://blah.com", {},
                              transport, base::Bind(success_callback),
                              base::Bind(error_callback));
}

TEST(HttpUtils, SendRequest_Headers) {
  std::shared_ptr<fake::Transport> transport(new fake::Transport);

  static const char json_echo_url[] = "http://localhost/echo/json";
  auto JsonEchoHandler = [](const fake::ServerRequest& request,
                            fake::ServerResponse* response) {
    base::Value json(base::Value::Type::DICTIONARY);
    json.SetStringKey("method", request.GetMethod());
    json.SetStringKey("data", request.GetDataAsString());
    for (const auto& pair : request.GetHeaders()) {
      json.SetStringPath("header." + pair.first, pair.second);
    }
    response->ReplyJson(status_code::Ok, &json);
  };
  transport->AddHandler(json_echo_url, "*", base::Bind(JsonEchoHandler));
  auto response =
      http::SendRequestAndBlock(request_type::kPost, json_echo_url, "abcd", 4,
                                brillo::mime::application::kOctet_stream,
                                {
                                    {request_header::kCookie, "flavor=vanilla"},
                                    {request_header::kIfMatch, "*"},
                                },
                                transport, nullptr);
  EXPECT_TRUE(response->IsSuccessful());
  EXPECT_EQ(brillo::mime::application::kJson,
            brillo::mime::RemoveParameters(response->GetContentType()));

  auto json = ParseJsonResponse(response.get(), nullptr, nullptr);
  const std::string* value = json->FindStringKey("method");
  ASSERT_TRUE(value);
  EXPECT_EQ(request_type::kPost, *value);

  value = json->FindStringKey("data");
  ASSERT_TRUE(value);
  EXPECT_EQ("abcd", *value);

  value = json->FindStringPath("header.Cookie");
  ASSERT_TRUE(value);
  EXPECT_EQ("flavor=vanilla", *value);

  value = json->FindStringPath("header.Content-Type");
  ASSERT_TRUE(value);
  EXPECT_EQ(brillo::mime::application::kOctet_stream, *value);

  value = json->FindStringPath("header.Content-Length");
  ASSERT_TRUE(value);
  EXPECT_EQ("4", *value);

  value = json->FindStringPath("header.If-Match");
  ASSERT_TRUE(value);
  EXPECT_EQ("*", *value);
}

TEST(HttpUtils, Get) {
  // Sends back the "?test=..." portion of URL.
  // So if we do GET "http://localhost?test=blah", this handler responds
  // with "blah" as text/plain.
  auto GetHandler = [](const fake::ServerRequest& request,
                       fake::ServerResponse* response) {
    EXPECT_EQ(request_type::kGet, request.GetMethod());
    EXPECT_EQ("0", request.GetHeader(request_header::kContentLength));
    EXPECT_EQ("", request.GetHeader(request_header::kContentType));
    response->ReplyText(status_code::Ok, request.GetFormField("test"),
                        brillo::mime::text::kPlain);
  };

  std::shared_ptr<fake::Transport> transport(new fake::Transport);
  transport->AddHandler(kFakeUrl, request_type::kGet, base::Bind(GetHandler));
  transport->AddHandler(kMethodEchoUrl, "*", base::Bind(EchoMethodHandler));

  // Make sure Get() actually does the GET request
  auto response = http::GetAndBlock(kMethodEchoUrl, {}, transport, nullptr);
  EXPECT_TRUE(response->IsSuccessful());
  EXPECT_EQ(brillo::mime::text::kPlain, response->GetContentType());
  EXPECT_EQ(request_type::kGet, response->ExtractDataAsString());

  for (std::string data : {"blah", "some data", ""}) {
    std::string url = brillo::url::AppendQueryParam(kFakeUrl, "test", data);
    response = http::GetAndBlock(url, {}, transport, nullptr);
    EXPECT_EQ(data, response->ExtractDataAsString());
  }
}

TEST(HttpUtils, Head) {
  auto HeadHandler = [](const fake::ServerRequest& request,
                        fake::ServerResponse* response) {
    EXPECT_EQ(request_type::kHead, request.GetMethod());
    EXPECT_EQ("0", request.GetHeader(request_header::kContentLength));
    EXPECT_EQ("", request.GetHeader(request_header::kContentType));
    response->ReplyText(status_code::Ok, "blah", brillo::mime::text::kPlain);
  };

  std::shared_ptr<fake::Transport> transport(new fake::Transport);
  transport->AddHandler(kFakeUrl, request_type::kHead, base::Bind(HeadHandler));

  auto response = http::HeadAndBlock(kFakeUrl, transport, nullptr);
  EXPECT_TRUE(response->IsSuccessful());
  EXPECT_EQ(brillo::mime::text::kPlain, response->GetContentType());
  EXPECT_EQ("", response->ExtractDataAsString());  // Must not have actual body.
  EXPECT_EQ("4", response->GetHeader(request_header::kContentLength));
}

TEST(HttpUtils, PostBinary) {
  auto Handler = [](const fake::ServerRequest& request,
                    fake::ServerResponse* response) {
    EXPECT_EQ(request_type::kPost, request.GetMethod());
    EXPECT_EQ("256", request.GetHeader(request_header::kContentLength));
    EXPECT_EQ(brillo::mime::application::kOctet_stream,
              request.GetHeader(request_header::kContentType));
    const auto& data = request.GetData();
    EXPECT_EQ(256, data.size());

    // Sum up all the bytes.
    int sum = std::accumulate(data.begin(), data.end(), 0);
    EXPECT_EQ(32640, sum);  // sum(i, i => [0, 255]) = 32640.
    response->ReplyText(status_code::Ok, "", brillo::mime::text::kPlain);
  };

  std::shared_ptr<fake::Transport> transport(new fake::Transport);
  transport->AddHandler(kFakeUrl, request_type::kPost, base::Bind(Handler));

  /// Fill the data buffer with bytes from 0x00 to 0xFF.
  std::vector<uint8_t> data(256);
  std::iota(data.begin(), data.end(), 0);

  auto response = http::PostBinaryAndBlock(kFakeUrl, data.data(), data.size(),
                                           mime::application::kOctet_stream, {},
                                           transport, nullptr);
  EXPECT_TRUE(response->IsSuccessful());
}

TEST(HttpUtils, PostText) {
  std::string fake_data = "Some data";
  auto post_handler = base::Bind(
      [](const std::string& data, const fake::ServerRequest& request,
         fake::ServerResponse* response) {
        EXPECT_EQ(request_type::kPost, request.GetMethod());
        EXPECT_EQ(
            data.size(),
            std::stoul(request.GetHeader(request_header::kContentLength)));
        EXPECT_EQ(brillo::mime::text::kPlain,
                  request.GetHeader(request_header::kContentType));
        response->ReplyText(status_code::Ok, request.GetDataAsString(),
                            brillo::mime::text::kPlain);
      },
      fake_data);

  std::shared_ptr<fake::Transport> transport(new fake::Transport);
  transport->AddHandler(kFakeUrl, request_type::kPost, post_handler);

  auto response = http::PostTextAndBlock(
      kFakeUrl, fake_data, brillo::mime::text::kPlain, {}, transport, nullptr);
  EXPECT_TRUE(response->IsSuccessful());
  EXPECT_EQ(brillo::mime::text::kPlain, response->GetContentType());
  EXPECT_EQ(fake_data, response->ExtractDataAsString());
}

TEST(HttpUtils, PostFormData) {
  std::shared_ptr<fake::Transport> transport(new fake::Transport);
  transport->AddHandler(kFakeUrl, request_type::kPost,
                        base::Bind(EchoDataHandler));

  auto response = http::PostFormDataAndBlock(kFakeUrl,
                                             {
                                                 {"key", "value"},
                                                 {"field", "field value"},
                                             },
                                             {}, transport, nullptr);
  EXPECT_TRUE(response->IsSuccessful());
  EXPECT_EQ(brillo::mime::application::kWwwFormUrlEncoded,
            response->GetContentType());
  EXPECT_EQ("key=value&field=field+value", response->ExtractDataAsString());
}

TEST(HttpUtils, PostMultipartFormData) {
  std::shared_ptr<fake::Transport> transport(new fake::Transport);
  transport->AddHandler(kFakeUrl, request_type::kPost,
                        base::Bind(EchoDataHandler));

  std::unique_ptr<FormData> form_data{new FormData{"boundary123"}};
  form_data->AddTextField("key1", "value1");
  form_data->AddTextField("key2", "value2");
  std::string expected_content_type = form_data->GetContentType();
  auto response = http::PostFormDataAndBlock(kFakeUrl, std::move(form_data), {},
                                             transport, nullptr);
  EXPECT_TRUE(response->IsSuccessful());
  EXPECT_EQ(expected_content_type, response->GetContentType());
  const char expected_value[] =
      "--boundary123\r\n"
      "Content-Disposition: form-data; name=\"key1\"\r\n"
      "\r\n"
      "value1\r\n"
      "--boundary123\r\n"
      "Content-Disposition: form-data; name=\"key2\"\r\n"
      "\r\n"
      "value2\r\n"
      "--boundary123--\r\n";
  EXPECT_EQ(expected_value, response->ExtractDataAsString());
}

TEST(HttpUtils, PostPatchJson) {
  auto JsonHandler = [](const fake::ServerRequest& request,
                        fake::ServerResponse* response) {
    auto mime_type = brillo::mime::RemoveParameters(
        request.GetHeader(request_header::kContentType));
    EXPECT_EQ(brillo::mime::application::kJson, mime_type);
    response->ReplyJson(status_code::Ok,
                        {
                            {"method", request.GetMethod()},
                            {"data", request.GetDataAsString()},
                        });
  };
  std::shared_ptr<fake::Transport> transport(new fake::Transport);
  transport->AddHandler(kFakeUrl, "*", base::Bind(JsonHandler));

  base::Value json(base::Value::Type::DICTIONARY);
  json.SetStringKey("key1", "val1");
  json.SetStringKey("key2", "val2");
  const std::string* value;

  // Test POST
  auto response =
      http::PostJsonAndBlock(kFakeUrl, &json, {}, transport, nullptr);
  auto resp_json = http::ParseJsonResponse(response.get(), nullptr, nullptr);
  ASSERT_TRUE(resp_json);

  value = resp_json->FindStringKey("method");
  ASSERT_TRUE(value);
  EXPECT_EQ(request_type::kPost, *value);

  value = resp_json->FindStringKey("data");
  ASSERT_TRUE(value);
  EXPECT_EQ("{\"key1\":\"val1\",\"key2\":\"val2\"}", *value);

  // Test PATCH
  response = http::PatchJsonAndBlock(kFakeUrl, &json, {}, transport, nullptr);
  resp_json = http::ParseJsonResponse(response.get(), nullptr, nullptr);
  ASSERT_TRUE(resp_json);

  value = resp_json->FindStringKey("method");
  ASSERT_TRUE(value);
  EXPECT_EQ(request_type::kPatch, *value);

  value = resp_json->FindStringKey("data");
  ASSERT_TRUE(value);
  EXPECT_EQ("{\"key1\":\"val1\",\"key2\":\"val2\"}", *value);
}

TEST(HttpUtils, ParseJsonResponse) {
  auto JsonHandler = [](const fake::ServerRequest& request,
                        fake::ServerResponse* response) {
    int status_code = std::stoi(request.GetFormField("code"));
    response->ReplyJson(status_code, {{"data", request.GetFormField("value")}});
  };
  std::shared_ptr<fake::Transport> transport(new fake::Transport);
  transport->AddHandler(kFakeUrl, request_type::kPost, base::Bind(JsonHandler));

  // Test valid JSON responses (with success or error codes).
  for (auto item : {"200;data", "400;wrong", "500;Internal Server error"}) {
    auto pair = brillo::string_utils::SplitAtFirst(item, ";");
    auto response = http::PostFormDataAndBlock(kFakeUrl,
                                               {
                                                   {"code", pair.first},
                                                   {"value", pair.second},
                                               },
                                               {}, transport, nullptr);
    int code = 0;
    auto json = http::ParseJsonResponse(response.get(), &code, nullptr);
    ASSERT_TRUE(json);
    const std::string* value = json->FindStringKey("data");
    ASSERT_TRUE(value);
    EXPECT_EQ(pair.first, brillo::string_utils::ToString(code));
    EXPECT_EQ(pair.second, *value);
  }

  // Test invalid (non-JSON) response.
  auto response = http::GetAndBlock("http://bad.url", {}, transport, nullptr);
  EXPECT_EQ(status_code::NotFound, response->GetStatusCode());
  EXPECT_EQ(brillo::mime::text::kHtml, response->GetContentType());
  int code = 0;
  auto json = http::ParseJsonResponse(response.get(), &code, nullptr);
  EXPECT_FALSE(json);
  EXPECT_EQ(status_code::NotFound, code);
}

TEST(HttpUtils, SendRequest_Failure) {
  std::shared_ptr<fake::Transport> transport(new fake::Transport);
  transport->AddHandler(kMethodEchoUrl, "*", base::Bind(EchoMethodHandler));
  ErrorPtr error;
  Error::AddTo(&error, FROM_HERE, "test_domain", "test_code", "Test message");
  transport->SetCreateConnectionError(std::move(error));
  error.reset();  // Just to make sure it is empty...
  auto response = http::SendRequestWithNoDataAndBlock(
      request_type::kGet, "http://blah.com", {}, transport, &error);
  EXPECT_EQ(nullptr, response.get());
  EXPECT_EQ("test_domain", error->GetDomain());
  EXPECT_EQ("test_code", error->GetCode());
  EXPECT_EQ("Test message", error->GetMessage());
}

TEST(HttpUtils, SendRequestAsync_Failure) {
  std::shared_ptr<fake::Transport> transport(new fake::Transport);
  transport->AddHandler(kMethodEchoUrl, "*", base::Bind(EchoMethodHandler));
  ErrorPtr error;
  Error::AddTo(&error, FROM_HERE, "test_domain", "test_code", "Test message");
  transport->SetCreateConnectionError(std::move(error));
  auto success_callback = [](RequestID /* request_id */,
                             std::unique_ptr<http::Response> /* response */) {
    FAIL() << "This callback shouldn't have been called";
  };
  auto error_callback = [](RequestID /* request_id */, const Error* error) {
    EXPECT_EQ("test_domain", error->GetDomain());
    EXPECT_EQ("test_code", error->GetCode());
    EXPECT_EQ("Test message", error->GetMessage());
  };
  http::SendRequestWithNoData(request_type::kGet, "http://blah.com", {},
                              transport, base::Bind(success_callback),
                              base::Bind(error_callback));
}

TEST(HttpUtils, GetCanonicalHeaderName) {
  EXPECT_EQ("Foo", GetCanonicalHeaderName("foo"));
  EXPECT_EQ("Bar", GetCanonicalHeaderName("BaR"));
  EXPECT_EQ("Baz", GetCanonicalHeaderName("BAZ"));
  EXPECT_EQ("Foo-Bar", GetCanonicalHeaderName("foo-bar"));
  EXPECT_EQ("Foo-Bar-Baz", GetCanonicalHeaderName("foo-Bar-BAZ"));
  EXPECT_EQ("Foo-Bar-Baz", GetCanonicalHeaderName("FOO-BAR-BAZ"));
  EXPECT_EQ("Foo-Bar-", GetCanonicalHeaderName("fOO-bAR-"));
  EXPECT_EQ("-Bar", GetCanonicalHeaderName("-bAR"));
  EXPECT_EQ("", GetCanonicalHeaderName(""));
  EXPECT_EQ("A-B-C", GetCanonicalHeaderName("a-B-c"));
}

}  // namespace http
}  // namespace brillo
