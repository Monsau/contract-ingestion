"""
S3 Client for fetching sample data from AWS S3
"""
import boto3
import json
import csv
import io
import logging
from typing import List, Dict, Any, Optional
from botocore.exceptions import ClientError, NoCredentialsError

logger = logging.getLogger(__name__)

class S3SampleDataClient:
    """Client for fetching sample data from S3"""
    
    def __init__(self, aws_access_key_id: str, aws_secret_access_key: str, aws_session_token: str, region: str = 'eu-west-1'):
        """Initialize S3 client with provided credentials"""
        try:
            self.s3_client = boto3.client(
                's3',
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                aws_session_token=aws_session_token,
                region_name=region
            )
            logger.info("✅ S3 client initialized successfully")
        except Exception as e:
            logger.error(f"❌ Failed to initialize S3 client: {e}")
            raise
    
    def list_objects_in_bucket(self, bucket_name: str, prefix: str = '', max_keys: int = 10) -> List[str]:
        """List objects in S3 bucket with optional prefix filter"""
        try:
            response = self.s3_client.list_objects_v2(
                Bucket=bucket_name,
                Prefix=prefix,
                MaxKeys=max_keys
            )
            
            objects = []
            if 'Contents' in response:
                for obj in response['Contents']:
                    objects.append(obj['Key'])
                    
            logger.info(f"📁 Found {len(objects)} objects in bucket {bucket_name} with prefix '{prefix}'")
            return objects
            
        except ClientError as e:
            logger.error(f"❌ Failed to list objects in bucket {bucket_name}: {e}")
            return []
    
    def fetch_sample_data_from_s3(self, bucket_name: str, object_key: str, max_rows: int = 10) -> List[Dict[str, Any]]:
        """Fetch sample data from S3 object (supports JSON, CSV, and plain text)"""
        try:
            logger.info(f"📥 Fetching sample data from s3://{bucket_name}/{object_key}")
            
            # Get the object from S3
            response = self.s3_client.get_object(Bucket=bucket_name, Key=object_key)
            content = response['Body'].read()
            
            # Determine file type from extension or content
            if object_key.lower().endswith('.json') or object_key.lower().endswith('.jsonl'):
                return self._parse_json_data(content, max_rows)
            elif object_key.lower().endswith('.csv'):
                return self._parse_csv_data(content, max_rows)
            elif object_key.lower().endswith('.parquet'):
                return self._parse_parquet_data(content, max_rows)
            else:
                # Try to parse as JSON first, then fallback to text
                try:
                    return self._parse_json_data(content, max_rows)
                except:
                    return self._parse_text_data(content, max_rows)
                    
        except ClientError as e:
            logger.error(f"❌ Failed to fetch data from s3://{bucket_name}/{object_key}: {e}")
            return []
        except Exception as e:
            logger.error(f"❌ Error processing data from s3://{bucket_name}/{object_key}: {e}")
            return []
    
    def _parse_json_data(self, content: bytes, max_rows: int) -> List[Dict[str, Any]]:
        """Parse JSON or JSONL data"""
        try:
            content_str = content.decode('utf-8')
            
            # Try parsing as JSON array first
            try:
                data = json.loads(content_str)
                if isinstance(data, list):
                    return data[:max_rows]
                elif isinstance(data, dict):
                    return [data]
            except json.JSONDecodeError:
                pass
            
            # Try parsing as JSONL (one JSON object per line)
            lines = content_str.strip().split('\n')
            results = []
            for line in lines[:max_rows]:
                if line.strip():
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return results
            
        except Exception as e:
            logger.error(f"❌ Failed to parse JSON data: {e}")
            return []
    
    def _parse_csv_data(self, content: bytes, max_rows: int) -> List[Dict[str, Any]]:
        """Parse CSV data"""
        try:
            content_str = content.decode('utf-8')
            csv_reader = csv.DictReader(io.StringIO(content_str))
            
            results = []
            for i, row in enumerate(csv_reader):
                if i >= max_rows:
                    break
                results.append(dict(row))
                
            return results
            
        except Exception as e:
            logger.error(f"❌ Failed to parse CSV data: {e}")
            return []
    
    def _parse_parquet_data(self, content: bytes, max_rows: int) -> List[Dict[str, Any]]:
        """Parse Parquet data (requires pandas)"""
        try:
            import pandas as pd
            df = pd.read_parquet(io.BytesIO(content))
            return df.head(max_rows).to_dict('records')
        except ImportError:
            logger.warning("📦 Pandas not available for Parquet parsing, skipping")
            return []
        except Exception as e:
            logger.error(f"❌ Failed to parse Parquet data: {e}")
            return []
    
    def _parse_text_data(self, content: bytes, max_rows: int) -> List[Dict[str, Any]]:
        """Parse plain text data as simple records"""
        try:
            content_str = content.decode('utf-8')
            lines = content_str.strip().split('\n')[:max_rows]
            
            results = []
            for i, line in enumerate(lines):
                if line.strip():
                    results.append({
                        'line_number': i + 1,
                        'content': line.strip()
                    })
                    
            return results
            
        except Exception as e:
            logger.error(f"❌ Failed to parse text data: {e}")
            return []
    
    def fetch_sample_data_from_contract_location(self, bucket_name: str, s3_path: str, table_name: str, max_rows: int = 10) -> List[Dict[str, Any]]:
        """Fetch sample data from S3 using contract-specified location"""
        try:
            logger.info(f"📥 Fetching sample data from contract location: s3://{bucket_name}/{s3_path}")
            
            # Parse the S3 path to understand the pattern
            # Example: enode/landing/*/*/*/generalEvents-*.json
            path_parts = s3_path.split('/')
            base_path = '/'.join(path_parts[:-1])  # enode/landing
            file_pattern = path_parts[-1] if path_parts else '*'  # generalEvents-*.json
            
            # List objects in the base path
            prefix = base_path.replace('*', '').rstrip('/')
            logger.info(f"🔍 Looking for files with prefix: {prefix}")
            
            objects = self.list_objects_in_bucket(bucket_name, prefix=prefix, max_keys=20)
            
            if not objects:
                logger.warning(f"⚠️ No objects found in s3://{bucket_name}/{prefix}")
                return []
            
            # Filter objects based on the file pattern
            matching_objects = []
            pattern_without_wildcards = file_pattern.replace('*', '').replace('-', '_').lower()
            
            for obj_key in objects:
                obj_filename = obj_key.split('/')[-1].lower()
                # Look for files that match the pattern or contain relevant keywords
                if (pattern_without_wildcards in obj_filename or 
                    'event' in obj_filename or 
                    table_name.lower() in obj_filename or
                    any(keyword in obj_filename for keyword in ['credential', 'inverter', 'vehicle', 'charging'])):
                    matching_objects.append(obj_key)
            
            if not matching_objects:
                logger.warning(f"⚠️ No matching files found for pattern {file_pattern} in s3://{bucket_name}/{prefix}")
                return []
            
            # Try to fetch data from the first few matching files
            for obj_key in matching_objects[:3]:  # Try up to 3 files
                sample_data = self.fetch_sample_data_from_s3(bucket_name, obj_key, max_rows)
                if sample_data:
                    logger.info(f"✅ Successfully fetched {len(sample_data)} records from {obj_key}")
                    return sample_data
            
            return []
            
        except Exception as e:
            logger.error(f"❌ Failed to fetch data from contract location: {e}")
            return []

    def find_sample_data_for_table(self, bucket_name: str, table_name: str, max_rows: int = 10) -> List[Dict[str, Any]]:
        """Find and fetch sample data for a specific table by searching for matching files"""
        try:
            # Search for files that might contain data for this table
            search_patterns = [
                f"{table_name.lower()}",
                f"{table_name.lower().replace('bronze', '')}",
                f"{table_name.lower().replace('_', '-')}",
                f"{table_name.lower().replace('enode', '')}",
            ]
            
            for pattern in search_patterns:
                # List objects with this pattern
                objects = self.list_objects_in_bucket(bucket_name, prefix=pattern, max_keys=50)
                
                if not objects:
                    # Try searching in common data directories
                    for data_dir in ['data/', 'raw/', 'bronze/', 'events/']:
                        objects = self.list_objects_in_bucket(bucket_name, prefix=f"{data_dir}{pattern}", max_keys=50)
                        if objects:
                            break
                
                if objects:
                    logger.info(f"🎯 Found {len(objects)} potential files for table {table_name}")
                    
                    # Try to fetch data from the first suitable file
                    for obj_key in objects[:3]:  # Try up to 3 files
                        sample_data = self.fetch_sample_data_from_s3(bucket_name, obj_key, max_rows)
                        if sample_data:
                            logger.info(f"✅ Successfully fetched {len(sample_data)} sample records from {obj_key}")
                            return sample_data
            
            logger.warning(f"⚠️ No sample data found for table {table_name} in bucket {bucket_name}")
            return []
            
        except Exception as e:
            logger.error(f"❌ Failed to find sample data for table {table_name}: {e}")
            return []