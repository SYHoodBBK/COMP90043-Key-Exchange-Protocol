# 使用官方Python运行时作为父镜像
FROM python:3.9-slim

# 设置工作目录
WORKDIR /app

# 将当前目录内容复制到容器的/app
COPY . /app

# 安装项目依赖
RUN pip install --no-cache-dir -r requirements.txt

# 暴露端口5000供Flask使用
EXPOSE 5000

# 暴露端口23456供WebSocket服务器使用
EXPOSE 23456

# 运行app.py
CMD ["python", "app.py"]
