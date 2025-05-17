import socket
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, ObjectIdentifier
from cryptography.x509 import SubjectAlternativeName
from cryptography.x509.general_name import OtherName
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from pyasn1.type import char
from pyasn1.codec.der.encoder import encode as der_encode

# 서버 정보
SERVER_IP = '127.0.0.1'
SERVER_PORT = 12345

def verify_cert_chain(signed_cert_path: str, ca_cert_path: str) -> bool:
    with open(signed_cert_path, "rb") as f:
        signed_cert = x509.load_pem_x509_certificate(f.read())

    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    ca_public_key = ca_cert.public_key()

    try:
        ca_public_key.verify(
            signed_cert.signature,
            signed_cert.tbs_certificate_bytes,
            ec.ECDSA(signed_cert.signature_hash_algorithm),
        )
        print("서명 검증 성공: 인증서가 CA에 의해 서명되었습니다.")
        return True
    except InvalidSignature:
        print("서명 검증 실패: 인증서가 CA에 의해 서명되지 않았거나 변조되었습니다.")
        return False
    except Exception as e:
        print(f"검증 중 오류 발생: {e}")
        return False

def print_cert_details(cert: x509.Certificate):
    print("----- 인증서 상세 정보 -----")
    print(f"Subject: {cert.subject.rfc4514_string()}")
    print(f"Issuer: {cert.issuer.rfc4514_string()}")
    print(f"Serial Number: {cert.serial_number}")
    print(f"Valid From: {cert.not_valid_before_utc}")
    print(f"Valid To: {cert.not_valid_after_utc}")

    print("\n확장 필드:")
    for ext in cert.extensions:
        print(f"- {ext.oid._name} (Critical={ext.critical}):")
        print(f"  {ext.value}")

def main():
    # 1. ECC 키 쌍 생성 (SECP256R1)
    private_key = ec.generate_private_key(ec.SECP256R1())

    # 2. 기기 ID와 OID 정의
    device_id = "DEVICE1"
    device_id_oid = ObjectIdentifier("1.3.6.1.4.1.2539.1.1")

    # 3. 기기 ID를 ASN.1 UTF8String 형식으로 DER 인코딩
    device_id_der = der_encode(char.UTF8String(device_id))

    # 4. CSR 생성기 생성 및 subject 설정
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"KR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyClient"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"MyClientDevice"),
    ]))

    # 5. SubjectAlternativeName 확장에 OtherName (기기 ID) 추가
    csr_builder = csr_builder.add_extension(
        SubjectAlternativeName([
            OtherName(device_id_oid, device_id_der)
        ]),
        critical=False,
    )

    # 6. ExtendedKeyUsage 확장에 사용목적 추가
    csr_builder = csr_builder.add_extension(
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CLIENT_AUTH,
        ]),
        critical=False,
    )

    # 7. CSR 서명 (SHA256)
    csr = csr_builder.sign(private_key, hashes.SHA256())

    # 8. PEM 직렬화
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    # 9. CSR 전송 및 서명된 인증서 수신
    with socket.create_connection((SERVER_IP, SERVER_PORT)) as sock:
        sock.sendall(csr_pem)
        response = sock.recv(10 * 1024)
        print("서버로부터 받은 인증서 PEM:\n")
        print(response.decode())

        with open("signed_cert.pem", "wb") as f:
            f.write(response)

    # 10. getCert 전송 및 서버 인증서 수신
    with socket.create_connection((SERVER_IP, SERVER_PORT)) as sock:
        sock.sendall(b"getCert")
        response = sock.recv(8192)
        print("서버 인증서 PEM:\n")
        print(response.decode())

        with open("server_cert.pem", "wb") as f:
            f.write(response)

    # 11. 인증서 상세 정보 출력
    with open("signed_cert.pem", "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
        print_cert_details(cert)

    # 12. 인증서 체인 검증 실행
    print("\n=== 인증서 체인 검증 시작 ===")
    verify_cert_chain("signed_cert.pem", "server_cert.pem")

if __name__ == "__main__":
    main()
