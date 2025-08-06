#!/usr/bin/env python3
"""
Script to fix the final stage issue in app.py
"""

import re

def fix_final_stage():
    # Read the file
    with open('app.py', 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    # Fix the get_next_stage method for stage 20.2
    pattern = r'(elif current_stage_num == 20\.2:\s+if action == \'approved\':\s+)return Stage\.query\.filter_by\(stage_number=21\.0\)\.first\(\)\s+# END'
    replacement = r'\1# This is the final stage - application is completed\n                # Certificate generation will be triggered by the completion status\n                return current_stage  # Stay on 20.2 but mark as completed'
    
    content = re.sub(pattern, replacement, content, flags=re.MULTILINE | re.DOTALL)
    
    # Fix syntax errors in move_application method definition
    content = re.sub(r'def move_application\(self application action reason=None user_id=None\):', 
                     'def move_application(self, application, action, reason=None, user_id=None):', content)
    
    # Fix the get_next_stage call
    content = re.sub(r'next_stage = self\.get_next_stage\(current_stage action\)', 
                     'next_stage = self.get_next_stage(current_stage, action)', content)
    
    # Fix missing commas in return dictionary
    content = re.sub(r"'success': False\s+'message':", "'success': False,\n                    'message':", content)
    
    # Fix missing commas in ApplicationHistory constructor
    content = re.sub(r'application_id=application\.id\s+from_stage_id=old_stage\.id', 
                     'application_id=application.id,\n                from_stage_id=old_stage.id', content)
    content = re.sub(r'from_stage_id=old_stage\.id\s+to_stage_id=next_stage\.id', 
                     'from_stage_id=old_stage.id,\n                to_stage_id=next_stage.id', content)
    content = re.sub(r'to_stage_id=next_stage\.id\s+action=action', 
                     'to_stage_id=next_stage.id,\n                action=action', content)
    content = re.sub(r'action=action\s+reason=reason', 
                     'action=action,\n                reason=reason', content)
    content = re.sub(r'reason=reason\s+moved_by_user_id=user_id', 
                     'reason=reason,\n                moved_by_user_id=user_id', content)
    
    # Fix client upload stage numbers
    content = re.sub(r'if current_stage\.stage_number in \[4\.2 13\.2\]:', 
                     'if current_stage.stage_number in [4.2, 13.2]:', content)
    
    # Fix get_next_stage call in handle_client_upload
    content = re.sub(r'next_stage = self\.get_next_stage\(current_stage \'client_upload_received\'\)', 
                     'next_stage = self.get_next_stage(current_stage, \'client_upload_received\')', content)
    
    # Add special handling for final stage in move_application
    final_stage_handling = '''
            # Special handling for final stage completion
            if not next_stage and current_stage.stage_number == 20.2 and action == 'approved':
                # This is the final stage - mark application as completed
                application.status = 'Completed'
                application.last_updated = datetime.utcnow()
                
                # Create history record for completion
                history = ApplicationHistory(
                    application_id=application.id,
                    from_stage_id=current_stage.id,
                    to_stage_id=current_stage.id,  # Stay on same stage
                    action=action,
                    reason=reason or 'Application completed - ready for certificate generation',
                    moved_by_user_id=user_id
                )
                
                db.session.add(history)
                db.session.commit()
                logger.info('Application marked as completed - ready for certificate generation')
                
                # Send completion notifications
                self.email_service.send_stage_notification(
                    application=application,
                    action='completed',
                    new_stage=current_stage,
                    reason='Application has been completed and is ready for certificate generation.',
                    notification_type='approved'
                )
                
                return {
                    'success': True,
                    'message': 'Application completed successfully - ready for certificate generation',
                    'new_stage': current_stage,
                    'completed': True
                }

'''
    
    # Insert the final stage handling before the "if not next_stage:" check
    content = re.sub(r'(\s+)if not next_stage:', 
                     final_stage_handling + r'\1if not next_stage:', content)
    
    # Write the fixed content back
    with open('app.py', 'w', encoding='utf-8') as f:
        f.write(content)
    
    print("Fixed final stage issue and syntax errors in app.py")

if __name__ == '__main__':
    fix_final_stage()