from setuptools import setup, find_packages

setup(
    name="netlify-site-clone",
    description="tool for cloning Netlify sites",
    long_description=open("README.md").read(),  # no "with..." will do for setup.py
    long_description_content_type="text/markdown; charset=UTF-8; variant=GFM",
    license="MIT",
    author="Kyrylo Shpytsya",
    author_email="kshpitsa@gmail.com",
    url="https://github.com/kshpytsya/netlify-site-clone",
    install_requires=[
        "click>=7.0,<8",
        "click-log>=0.3.2,<1",
        "dnspython>=1.16.0,<2",
        "requests>=2.21.0,<3",
    ],
    setup_requires=["setuptools_scm"],
    use_scm_version=True,
    python_requires=">=3.6, <3.8",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    entry_points={
        "console_scripts": ["netlify-site-clone = netlify_site_clone._cli:main"]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
        "Topic :: System :: Systems Administration",
    ],
)
