from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
import hashlib
import json

# ===== 任务1：对交易数据签名（补全）=====
def sign_transaction(tx_dict, private_key):
    """
    对交易字典进行ECDSA签名
    :param tx_dict: 待签名的交易字典
    :param private_key: 椭圆曲线私钥对象
    :return: 字节类型的签名数据
    """
    # 1. 将交易字典转为有序字符串（保证序列化结果唯一）
    # sort_keys=True 确保字典键值对顺序固定，避免相同内容不同顺序导致哈希不一致
    tx_string = json.dumps(tx_dict, sort_keys=True).encode('utf-8')
    
    # 2. 计算交易数据的SHA256哈希
    tx_hash = hashlib.sha256(tx_string).digest()
    
    # 3. 用私钥进行ECDSA签名（使用SHA256哈希算法）
    # signature_algorithm=ec.ECDSA(hashes.SHA256()) 指定签名算法
    signature = private_key.sign(
        tx_hash,
        ec.ECDSA(hashes.SHA256())
    )
    
    return signature

# ===== 任务2：验证签名 + 篡改检测（补全）=====
def verify_signature(tx_dict, signature, public_key):
    """
    验证交易签名的有效性，检测数据是否被篡改
    :param tx_dict: 待验证的交易字典
    :param signature: 签名字节数据
    :param public_key: 椭圆曲线公钥对象
    :return: bool - 验证通过返回True，否则返回False
    """
    try:
        # 1. 对交易数据做和签名时相同的哈希处理
        tx_string = json.dumps(tx_dict, sort_keys=True).encode('utf-8')
        tx_hash = hashlib.sha256(tx_string).digest()
        
        # 2. 用公钥验证签名
        public_key.verify(
            signature,
            tx_hash,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        # 签名不匹配（数据被篡改或签名错误）
        return False
    except Exception as e:
        # 其他异常（如数据格式错误）
        print(f"验证过程出错: {e}")
        return False

    # ===== 生成密钥对（已提供）=====
    private_key = ec.generate_private_key(ec.SECP256K1())
    public_key = private_key.public_key()
    print("密钥对生成完成...")

    signature = sign_transaction(tx_data, private_key)
    print(f"交易签名完成: {signature[:32]}...")

    # 正常验证
    is_valid = verify_signature(tx_data, signature, public_key)
    print(f"签名验证: {is_valid}")

    # 篡改测试：攻击者修改金额
    tampered_tx = tx_data.copy()
    tampered_tx["amount"] = 1000000
    is_tamper_detected = not verify_signature(tampered_tx, signature, public_key)
    print(f"篡改检测: {'成功🔒' if is_tamper_detected else '失败⚠️'}")
