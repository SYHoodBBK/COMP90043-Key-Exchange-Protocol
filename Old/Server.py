import socket
import json

# 全局列表来存储接收到的请求
requests_storage = []


def store_request(content):
    """处理存储请求"""
    requests_storage.append(content)
    return {"status": "success", "message": "数据已存储"}


def retrieve_requests(user):
    """处理检索请求"""
    user_requests = [
        request for request in requests_storage if request.get("user") == user]
    # 只发送第一条one_time_prekeys
    user_requests_copy = []
    for request in user_requests:
        request_copy = request.copy()
        request_copy["one_time_prekeys"] = request["one_time_prekeys"][0]
        user_requests_copy.append(request_copy)

    return {"status": "success", "content": user_requests_copy}



def update_request(index, new_content):
    """处理更新请求"""
    if 0 <= index < len(requests_storage):
        requests_storage[index] = new_content
        return {"status": "success", "message": "数据已更新"}
    else:
        return {"status": "error", "message": "索引无效"}


def delete_request(index):
    """处理删除请求"""
    if 0 <= index < len(requests_storage):
        del requests_storage[index]
        return {"status": "success", "message": "数据已删除"}
    else:
        return {"status": "error", "message": "索引无效"}


def start_server(host='localhost', port=65432):
    # 创建一个TCP/IP套接字
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # 绑定套接字到地址
        server_socket.bind((host, port))
        # 监听传入连接
        server_socket.listen()
        print(f"服务器启动，正在监听 {host}:{port}")

        while True:
            # 等待连接
            client_socket, client_address = server_socket.accept()
            with client_socket:
                print(f"连接来自 {client_address}")

                # 接收数据
                data = client_socket.recv(1024)
                if not data:
                    break

                # 解析收到的JSON数据
                try:
                    received_data = json.loads(data.decode('utf-8'))
                    print("收到的数据:", received_data)

                    # 根据请求类型处理请求
                    request_type = received_data.get("type")
                    if request_type == "store":
                        response = store_request(received_data.get("content"))
                    elif request_type == "retrieve":
                        response = retrieve_requests(received_data.get("user"))
                    elif request_type == "update":
                        response = update_request(
                            received_data.get("index"), received_data.get("content"))
                    elif request_type == "delete":
                        response = delete_request(received_data.get("index"))
                    else:
                        response = {"status": "error", "message": "未知请求类型"}
                    print("响应数据:", response)
                    # 发送响应消息
                    client_socket.sendall(json.dumps(response).encode('utf-8'))
                except json.JSONDecodeError:
                    print("收到无效数据")
                    response = {"status": "error", "message": "无效数据"}
                    client_socket.sendall(json.dumps(response).encode('utf-8'))


if __name__ == "__main__":
    start_server()
