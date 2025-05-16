import socket
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

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


def main():
    # ECC 키 쌍 생성
    private_key = ec.generate_private_key(ec.SECP256R1())

    # CSR 생성
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"KR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyClient"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"MyClientDevice"),
    ])).sign(private_key, hashes.SHA256())

    # PEM 형식으로 직렬화
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    # CSR 전송 및 서명된 인증서 수신
    with socket.create_connection((SERVER_IP, SERVER_PORT)) as sock:
        sock.sendall(csr_pem)
        response = sock.recv(10 * 1024)
        print("서버로부터 받은 인증서 PEM:\n")
        print(response.decode())

        with open("signed_cert.pem", "wb") as f:
            f.write(response)

    # getCert 전송 및 서버 인증서 수신
    with socket.create_connection((SERVER_IP, SERVER_PORT)) as sock:
        sock.sendall(b"getCert")
        response = sock.recv(8192)
        print("서버 인증서 PEM:\n")
        print(response.decode())

        with open("server_cert.pem", "wb") as f:
            f.write(response)

    # 검증 실행
    print("\n=== 인증서 체인 검증 시작 ===")
    verify_cert_chain("signed_cert.pem", "server_cert.pem")

if __name__ == "__main__":
    main()
