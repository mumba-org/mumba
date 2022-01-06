//
//  Copyright (C) 2017 Microsoft.  All rights reserved.
//  See LICENSE file in the project root for full license information.
// 
#include <memory>
#include <string>
#include <vector>
#include <map>

#include "Exceptions.hpp"
#include "StreamBase.hpp"
#include "IXml.hpp"
#include "Encoding.hpp"
#include "StreamHelper.hpp"
#include "MSIXResource.hpp"
#include "UnicodeConversion.hpp"
#include "Enumerators.hpp"
#include "JniHelper.hpp"

// An internal interface for java XML document object model
// {69AB3660-398D-4CD6-A131-E73106040E3B}
interface IJavaXmlElement : public IUnknown
{
public:
    virtual jobject GetJavaObject() = 0;
};
MSIX_INTERFACE(IJavaXmlElement,  0x69ab3660,0x398d,0x4cd6,0xa1,0x31,0xe7,0x31,0x6,0x4,0xe,0x3b);

namespace MSIX {

class JavaXmlElement final : public ComClass<JavaXmlElement, IXmlElement, IJavaXmlElement, IMsixElement>
{
public:
    JavaXmlElement(IMsixFactory* factory, jobject javaXmlElementObject) :
        m_factory(factory), m_javaXmlElementObject(javaXmlElementObject)
    {
        m_env = Jni::Instance()->GetEnv();
        std::unique_ptr<_jclass, JObjectDeleter> xmlElementClass(m_env->FindClass("com/microsoft/msix/XmlElement"));
       
        getAttributeValueFunc = m_env->GetMethodID(
                xmlElementClass.get(), "GetAttributeValue",
                "(Ljava/lang/String;)Ljava/lang/String;");
        getTextContentFunc = m_env->GetMethodID(
                xmlElementClass.get(), "GetTextContent",
                "()Ljava/lang/String;");
        getPrefixFunc = m_env->GetMethodID(
                xmlElementClass.get(), "GetPrefix",
                "()Ljava/lang/String;");
        getElementsByTagNameFunc = m_env->GetMethodID(
                xmlElementClass.get(), "GetElementsByTagName",
                "(Ljava/lang/String;)[Lcom/microsoft/msix/XmlElement;");
        getElementsFunc = m_env->GetMethodID(
                xmlElementClass.get(), "GetElements",
                "(Ljava/lang/String;)[Lcom/microsoft/msix/XmlElement;");
    }

    // IXmlElement
    std::string GetAttributeValue(XmlAttributeName attribute) override
    {
        auto intermediate = std::string(GetAttributeNameStringUtf8(attribute));
        return GetAttributeValue(intermediate);
    }

    std::vector<std::uint8_t> GetBase64DecodedAttributeValue(XmlAttributeName attribute) override
    {
        auto intermediate = GetAttributeValue(attribute);
        return Encoding::GetBase64DecodedValue(intermediate);
    }

    std::string GetText() override
    {
        std::unique_ptr<_jstring, JObjectDeleter> jvalue(reinterpret_cast<jstring>(m_env->CallObjectMethod(m_javaXmlElementObject.get(), getTextContentFunc)));
        return GetStringFromJString(jvalue.get());
    }

    std::string GetPrefix() override
    {
        std::unique_ptr<_jstring, JObjectDeleter> jvalue(reinterpret_cast<jstring>(m_env->CallObjectMethod(m_javaXmlElementObject.get(), getPrefixFunc)));
        if (jvalue.get() != nullptr)
        {
            std::string nodeName = GetStringFromJString(jvalue.get());
            std::size_t semiColon = nodeName.find_first_of(':');
            if (semiColon != std::string::npos)
            {
                return nodeName.substr(0, semiColon);
            }
        }
        return {};
    }

    // IJavaXmlElement
    jobject GetJavaObject() override { return m_javaXmlElementObject.get(); }

     // IMsixElement
    HRESULT STDMETHODCALLTYPE GetAttributeValue(LPCWSTR name, LPWSTR* value) noexcept override try
    {
        ThrowErrorIf(Error::InvalidParameter, (value == nullptr), "bad pointer.");
        auto intermediate = wstring_to_utf8(name);
        auto attributeValue = GetAttributeValue(intermediate);
        return m_factory->MarshalOutString(attributeValue, value);;
    } CATCH_RETURN();

    HRESULT STDMETHODCALLTYPE GetText(LPWSTR* value) noexcept override try
    {
        ThrowErrorIf(Error::InvalidParameter, (value == nullptr), "bad pointer.");
        auto text = GetText();
        return m_factory->MarshalOutString(text, value);
    } CATCH_RETURN();

    HRESULT STDMETHODCALLTYPE GetElements(LPCWSTR xpath, IMsixElementEnumerator** elements) noexcept override try
    {
        return GetElementsUtf8(wstring_to_utf8(xpath).c_str(), elements);
    } CATCH_RETURN();

    HRESULT STDMETHODCALLTYPE GetAttributeValueUtf8(LPCSTR name, LPSTR* value) noexcept override try
    {
        ThrowErrorIf(Error::InvalidParameter, (value == nullptr), "bad pointer.");
        auto attribute = std::string(name);
        auto attributeValue = GetAttributeValue(attribute);
        return m_factory->MarshalOutStringUtf8(attributeValue, value);;
    } CATCH_RETURN();

    HRESULT STDMETHODCALLTYPE GetTextUtf8(LPSTR* value) noexcept override try
    {
        ThrowErrorIf(Error::InvalidParameter, (value == nullptr), "bad pointer.");
        auto text = GetText();
        return m_factory->MarshalOutStringUtf8(text, value);
    } CATCH_RETURN();

    HRESULT STDMETHODCALLTYPE GetElementsUtf8(LPCSTR xpath, IMsixElementEnumerator** elements) noexcept override try
    {
        ThrowErrorIf(Error::InvalidParameter, (elements == nullptr || *elements != nullptr), "bad pointer.");
        std::unique_ptr<_jstring, JObjectDeleter> jname(m_env->NewStringUTF(xpath));
        std::unique_ptr<_jobjectArray, JObjectDeleter> javaElements(reinterpret_cast<jobjectArray>(m_env->CallObjectMethod(m_javaXmlElementObject.get(), getElementsFunc, jname.get())));
        std::vector<ComPtr<IMsixElement>> elementsEnum;
        // Note: if the number of elements are large, JNI might barf due to too many local refs alive. This should only be used for small lists.
        for(int i = 0; i < m_env->GetArrayLength(javaElements.get()); i++)
        {
            auto item = ComPtr<IMsixElement>::Make<JavaXmlElement>(m_factory, m_env->GetObjectArrayElement(javaElements.get(), i));
            elementsEnum.push_back(std::move(item));
        }
        *elements = ComPtr<IMsixElementEnumerator>::Make<EnumeratorCom<IMsixElementEnumerator,IMsixElement>>(elementsEnum).Detach();
        return static_cast<HRESULT>(Error::OK);
    } CATCH_RETURN();

private:
    IMsixFactory* m_factory = nullptr;
    std::unique_ptr<_jobject, JObjectDeleter> m_javaXmlElementObject;
    jmethodID getAttributeValueFunc = nullptr;
    jmethodID getTextContentFunc = nullptr;
    jmethodID getPrefixFunc = nullptr;
    jmethodID getElementsByTagNameFunc = nullptr;
    jmethodID getElementsFunc = nullptr;
    JNIEnv* m_env = nullptr;

    std::string GetAttributeValue(std::string& attributeName)
    {
        std::unique_ptr<_jstring, JObjectDeleter> jname(m_env->NewStringUTF(attributeName.c_str()));
        std::unique_ptr<_jstring, JObjectDeleter> jvalue(reinterpret_cast<jstring>(m_env->CallObjectMethod(m_javaXmlElementObject.get(), getAttributeValueFunc, jname.get())));
        return GetStringFromJString(jvalue.get());
    }
};

void CheckForJavaXmlParseException(JNIEnv* env)
{
    jboolean exceptionThrown = env->ExceptionCheck();
    if (exceptionThrown == JNI_TRUE) {
        std::unique_ptr<_jthrowable, JObjectDeleter> exc(env->ExceptionOccurred());
            env->ExceptionClear();

        std::unique_ptr<_jclass, JObjectDeleter> javaXmlExceptionClass(env->FindClass("com/microsoft/msix/JavaXmlException"));
        if (env->IsInstanceOf(exc.get(), javaXmlExceptionClass.get()) == JNI_TRUE)
        {
            jmethodID getErrorCodeFunc = env->GetMethodID(javaXmlExceptionClass.get(), "GetErrorCode", "()I");
            jint errorCode = env->CallIntMethod(exc.get(), getErrorCodeFunc);

            if (errorCode == 0)
            {
                ThrowError(MSIX::Error::XmlWarning);
            }
            else
            {
                // We treat all other parser errors as fatal.
                ThrowError(MSIX::Error::XmlFatal);
            }
        }

        std::unique_ptr<_jclass, JObjectDeleter> saxParseExceptionClass(env->FindClass("org/xml/sax/SAXParseException"));
        if (env->IsInstanceOf(exc.get(), saxParseExceptionClass.get()) == JNI_TRUE)
        {
                ThrowError(MSIX::Error::XmlFatal);
        }
    }
}

class JavaXmlDom final : public ComClass<JavaXmlDom, IXmlDom>
{
public:
    JavaXmlDom(IMsixFactory* factory, const ComPtr<IStream>& stream) :
        m_factory(factory), m_stream(stream)
    {
        m_env = Jni::Instance()->GetEnv();

        std::unique_ptr<_jclass, JObjectDeleter> xmlDomClass(m_env->FindClass("com/microsoft/msix/XmlDom"));

        getDocumentFunc = m_env->GetMethodID(
                    xmlDomClass.get(), "GetDocument",
                    "()Lcom/microsoft/msix/XmlElement;");

        getElementsFunc = m_env->GetMethodID(
                xmlDomClass.get(), "GetElements",
                "(Lcom/microsoft/msix/XmlElement;Ljava/lang/String;)[Lcom/microsoft/msix/XmlElement;");
        jmethodID ctor = m_env->GetMethodID(xmlDomClass.get(), "<init>", "()V");
        m_javaXmlDom.reset(m_env->NewObject(xmlDomClass.get(), ctor));

        auto buffer = Helper::CreateBufferFromStream(stream);
        std::unique_ptr<_jbyteArray, JObjectDeleter>  byteArray(m_env->NewByteArray(buffer.size()));
        m_env->SetByteArrayRegion(byteArray.get(), (jsize) 0, (jsize) buffer.size(), (jbyte*) buffer.data());
        jmethodID initializeFunc = m_env->GetMethodID(xmlDomClass.get(), "InitializeDocument", "([B)V");
        m_env->CallVoidMethod(m_javaXmlDom.get(), initializeFunc, byteArray.get());

        // android does not include any schema validation parsers. We can only support xml validation.
        // If schema validation is required, then use xerces as the xml parser.
    }

    // IXmlDom
    MSIX::ComPtr<IXmlElement> GetDocument() override
    {
        // Before returning document to caller, check to see if there were any JNI exceptions.
        CheckForJavaXmlParseException(m_env);

        std::unique_ptr<_jobject, JObjectDeleter> javaElement(m_env->CallObjectMethod(m_javaXmlDom.get(), getDocumentFunc));
        return ComPtr<IXmlElement>::Make<JavaXmlElement>(m_factory, javaElement.release());
    }

    bool ForEachElementIn(const ComPtr<IXmlElement>& root, XmlQueryName query, XmlVisitor& visitor) override
    {
        ComPtr<IJavaXmlElement> element = root.As<IJavaXmlElement>();

        std::unique_ptr<_jstring, JObjectDeleter> jquery(m_env->NewStringUTF(GetQueryString(query)));
        std::unique_ptr<_jobjectArray, JObjectDeleter> javaElements(reinterpret_cast<jobjectArray>(m_env->CallObjectMethod(m_javaXmlDom.get(), getElementsFunc, element->GetJavaObject(), jquery.get())));

        for(int i = 0; i < m_env->GetArrayLength(javaElements.get()); i++)
        {
            auto item = ComPtr<IXmlElement>::Make<JavaXmlElement>(m_factory, m_env->GetObjectArrayElement(javaElements.get(), i));
            if (!visitor(item))
            {
                return false;
            }
        }
        return true;
    }

protected:
    IMsixFactory* m_factory;
    ComPtr<IStream> m_stream;
    jmethodID getDocumentFunc = nullptr;
    jmethodID getElementsFunc = nullptr;
    std::unique_ptr<_jobject, JObjectDeleter> m_javaXmlDom;
    JNIEnv* m_env = nullptr;
};

class JavaXmlFactory final : public ComClass<JavaXmlFactory, IXmlFactory>
{
public:
    JavaXmlFactory(IMsixFactory* factory) : m_factory(factory)
    {
    }

    ComPtr<IXmlDom> CreateDomFromStream(XmlContentType footPrintType, const ComPtr<IStream>& stream) override
    {
        return ComPtr<IXmlDom>::Make<JavaXmlDom>(m_factory, stream);
    }
protected:
    IMsixFactory* m_factory;
};

ComPtr<IXmlFactory> CreateXmlFactory(IMsixFactory* factory) { return ComPtr<IXmlFactory>::Make<JavaXmlFactory>(factory); }

} // namespace MSIX