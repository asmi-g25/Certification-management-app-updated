
"""
Migration script to update ApplicationHistory and Document tables
Run this once to update your existing database schema
"""

from app import app, db, ApplicationHistory, Document
from sqlalchemy import text

def migrate_database():
    with app.app_context():
        try:
            print("Adding new columns to application_history table...")
            
            # Use connection.execute() instead of engine.execute()
            with db.engine.connect() as connection:
                # Start a transaction
                trans = connection.begin()
                
                try:
                    # Check if old stage_id column exists
                    result = connection.execute(text("""
                        SELECT column_name FROM information_schema.columns 
                        WHERE table_name='application_history' AND column_name='stage_id'
                    """))
                    has_old_stage_id = result.fetchone() is not None
                    
                    # Check if new columns exist
                    result = connection.execute(text("""
                        SELECT column_name FROM information_schema.columns 
                        WHERE table_name='application_history' AND column_name IN ('from_stage_id', 'to_stage_id', 'moved_by_user_id')
                    """))
                    existing_columns = [row[0] for row in result.fetchall()]
                    
                    # Add new columns if they don't exist
                    if 'from_stage_id' not in existing_columns:
                        connection.execute(text('''
                            ALTER TABLE application_history 
                            ADD COLUMN from_stage_id INTEGER REFERENCES stages(id)
                        '''))
                        print("Added from_stage_id column")
                    
                    if 'to_stage_id' not in existing_columns:
                        connection.execute(text('''
                            ALTER TABLE application_history 
                            ADD COLUMN to_stage_id INTEGER REFERENCES stages(id)
                        '''))
                        print("Added to_stage_id column")
                    
                    if 'moved_by_user_id' not in existing_columns:
                        connection.execute(text('''
                            ALTER TABLE application_history 
                            ADD COLUMN moved_by_user_id INTEGER REFERENCES users(id)
                        '''))
                        print("Added moved_by_user_id column")
                    
                    # Migrate data from old columns if they exist
                    if has_old_stage_id:
                        # Copy data from old stage_id to new to_stage_id
                        connection.execute(text('''
                            UPDATE application_history 
                            SET to_stage_id = stage_id
                            WHERE to_stage_id IS NULL AND stage_id IS NOT NULL
                        '''))
                        print("Migrated stage_id data to to_stage_id")
                        
                        # Check if old user_id column exists and migrate
                        result = connection.execute(text("""
                            SELECT column_name FROM information_schema.columns 
                            WHERE table_name='application_history' AND column_name='user_id'
                        """))
                        has_old_user_id = result.fetchone() is not None
                        
                        if has_old_user_id:
                            connection.execute(text('''
                                UPDATE application_history 
                                SET moved_by_user_id = user_id
                                WHERE moved_by_user_id IS NULL AND user_id IS NOT NULL
                            '''))
                            print("Migrated user_id data to moved_by_user_id")
                    
                    # Make to_stage_id NOT NULL after data migration
                    connection.execute(text('''
                        ALTER TABLE application_history 
                        ALTER COLUMN to_stage_id SET NOT NULL
                    '''))
                    print("Set to_stage_id as NOT NULL")
                    
                    # Drop old columns if they exist
                    if has_old_stage_id:
                        connection.execute(text('ALTER TABLE application_history DROP COLUMN IF EXISTS stage_id'))
                        print("Dropped old stage_id column")
                        
                        connection.execute(text('ALTER TABLE application_history DROP COLUMN IF EXISTS user_id'))
                        print("Dropped old user_id column")
                    
                    trans.commit()
                    print("Application history migration completed successfully!")
                    
                except Exception as e:
                    trans.rollback()
                    raise e
            
            print("Adding uploaded_by_user_id column to documents table...")
            
            # Check if uploaded_by_user_id column exists in documents table
            with db.engine.connect() as connection:
                trans = connection.begin()
                
                try:
                    result = connection.execute(text("""
                        SELECT column_name FROM information_schema.columns 
                        WHERE table_name='documents' AND column_name='uploaded_by_user_id'
                    """))
                    has_uploaded_by_user_id = result.fetchone() is not None
                    
                    if not has_uploaded_by_user_id:
                        connection.execute(text('''
                            ALTER TABLE documents 
                            ADD COLUMN uploaded_by_user_id INTEGER REFERENCES users(id)
                        '''))
                        print("Added uploaded_by_user_id column to documents table")
                    
                    trans.commit()
                    print("Documents table migration completed successfully!")
                    
                except Exception as e:
                    trans.rollback()
                    raise e
            
            print("Migration completed successfully!")
            
        except Exception as e:
            print(f"Migration error: {e}")
            raise

if __name__ == "__main__":
    migrate_database()
