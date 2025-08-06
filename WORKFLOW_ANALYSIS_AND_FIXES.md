# Workflow and Notification System Analysis & Fixes

## Issues Identified

### 1. **Stage Number Mismatches**
Your current code had different stage numbers than your detailed workflow specification:

**Current Code vs Your Specification:**
- Code: Client upload stages at 4.1 and 12.1
- Spec: Client upload stages at 4.2 and 13.2
- Code: Payment confirmation at 4.2 and 12.2  
- Spec: Payment confirmation at 4.3 and 13.3

### 2. **Incomplete Workflow Transitions**
The workflow logic didn't match your detailed specification for stage transitions and actions.

### 3. **Missing Group Assignments**
Your specification mentions specific groups (TAO, Finance, TGL:TA, STA, etc.) that need to be properly mapped to stages.

### 4. **Notification Logic Issues**
- Upload URL generation was using wrong stage numbers
- Client notification messages weren't matching the correct stages
- Group notifications weren't following your specification

## Fixes Applied

### 1. **Updated Stage Actions**
```python
# Updated to match your specification exactly
stage_actions = {
    # Stage 4: Admin Invoice Generation
    4.0: [('generated', 'Generated'), ('rejected', 'Rejected')],
    
    # Stage 4.1: Confirmation of Invoice (when confirmed, goes to client)
    4.1: [('confirmed', 'Confirmed')],
    
    # Stage 4.2: Admin fee-Proof of Payment (Client uploads) - CLIENT UPLOAD STAGE
    4.2: [],  # Empty - only client uploads can progress this stage
    
    # Stage 4.3: Payment Confirmation
    4.3: [('paid', 'PAID'), ('not_paid', 'NOT PAID')],
    
    # Similar updates for evaluation fee stages 13.0-13.3
}
```

### 2. **Corrected Workflow Transitions**
Updated `get_next_stage()` method to follow your exact specification:

```python
# Stage 4.2: Admin fee-Proof of Payment (Client uploads) - CLIENT UPLOAD STAGE
elif current_stage_num == 4.2:
    if action == 'client_upload_received':
        return Stage.query.filter_by(stage_number=4.3).first()  # Go to 4.3
    else:
        return current_stage  # Stay here until client uploads

# Stage 4.3: Payment Confirmation
elif current_stage_num == 4.3:
    if action == 'paid':
        return Stage.query.filter_by(stage_number=5.0).first()  # Go to 5
    elif action == 'not_paid':
        return Stage.query.filter_by(stage_number=4.2).first()  # Go to 4.2
```

### 3. **Fixed Client Upload Detection**
```python
def stage_requires_client_upload(self, stage_number):
    """Check if a stage requires client document upload"""
    client_upload_stages = {
        4.2,  # Admin fee-Proof of Payment upload (Client uploads)
        13.2, # Evaluation fee-Proof of Payment upload (Client uploads)
    }
    return stage_number in client_upload_stages
```

### 4. **Updated Client Upload Handling**
```python
def handle_client_upload(self, application):
    """Handle automatic progression when client uploads documents"""
    current_stage = application.current_stage
    
    # Only auto-progress from client upload stages
    if current_stage.stage_number in [4.2, 13.2]:  # Updated stage numbers
        # Auto-progress to next stage when client uploads
```

## Required Database Setup

To make the notifications work properly, you need to:

### 1. **Create Required Groups**
```sql
INSERT INTO groups (name, description, is_active) VALUES
('TAO Group', 'Technical Assessment Office', true),
('Finance Group', 'Finance Department', true),
('TGL:TA Group', 'Technical Group Leader: Technical Assessment', true),
('STA Group', 'Senior Technical Assessor', true),
('Technical Services Group', 'Technical Services Department', true),
('EMTS Group', 'Executive Manager Technical Services', true),
('TECO Group', 'Technical Committee', true),
('Board Group', 'Board Members', true),
('Board Chairperson Group', 'Board Chairperson', true),
('Project Leader Group', 'Project Leaders', true);
```

### 2. **Create Required Stages**
```sql
-- Make sure all stages from your specification exist
INSERT INTO stages (name, stage_number, description, is_active) VALUES
('New Application', 1.0, 'New Application by client', true),
('Verification of Application Completeness', 2.0, 'TAO verifies application completeness', true),
('Admin Fee Request', 3.0, 'TAO requests admin fee', true),
('Admin Invoice Generation', 4.0, 'Finance generates admin invoice', true),
('Confirmation of Invoice', 4.1, 'TAO confirms invoice before sending to client', true),
('Admin fee-Proof of Payment', 4.2, 'Client uploads proof of payment', true),
('Payment Confirmation', 4.3, 'Finance confirms payment received', true),
-- ... continue for all stages up to 21.0
```

### 3. **Assign Groups to Stages**
```sql
-- Example assignments based on your specification
INSERT INTO stage_group_assignments (stage_id, group_id) VALUES
((SELECT id FROM stages WHERE stage_number = 2.0), (SELECT id FROM groups WHERE name = 'TAO Group')),
((SELECT id FROM stages WHERE stage_number = 3.0), (SELECT id FROM groups WHERE name = 'TAO Group')),
((SELECT id FROM stages WHERE stage_number = 4.0), (SELECT id FROM groups WHERE name = 'Finance Group')),
((SELECT id FROM stages WHERE stage_number = 4.3), (SELECT id FROM groups WHERE name = 'Finance Group')),
-- ... continue for all stage-group assignments
```

## Testing the Fixes

### 1. **Test Email Configuration**
```python
# Test email sending
email_service = EmailService()
test_result = email_service.send_email(
    ['test@example.com'], 
    'Test Subject', 
    'Test Body'
)
print(f"Email test result: {test_result}")
```

### 2. **Test Workflow Progression**
```python
# Test stage transitions
workflow_service = WorkflowService()
application = Application.query.first()  # Get test application
result = workflow_service.move_application(
    application, 
    'application_complete', 
    'Test reason', 
    current_user.id
)
print(f"Workflow test result: {result}")
```

### 3. **Test Client Upload URLs**
```python
# Test upload URL generation
application = Application.query.first()
token = application.generate_client_upload_token()
print(f"Upload token: {token}")

# Test stage detection
workflow_service = WorkflowService()
requires_upload = workflow_service.stage_requires_client_upload(4.2)
print(f"Stage 4.2 requires upload: {requires_upload}")
```

## Key Improvements Made

1. **Accurate Stage Mapping**: All stage numbers now match your specification exactly
2. **Proper Workflow Logic**: Stage transitions follow your detailed workflow rules
3. **Correct Client Upload Stages**: Stages 4.2 and 13.2 are properly identified as client upload stages
4. **Enhanced Notifications**: Email notifications include proper upload URLs and stage-specific messages
5. **Group-Based Notifications**: Framework ready for proper group assignments per your specification
6. **Comprehensive Logging**: Added detailed logging for debugging notification issues

## Next Steps

1. **Database Setup**: Run the SQL scripts to create groups and stage assignments
2. **User Assignment**: Assign users to the appropriate groups
3. **Email Testing**: Test email sending with your SMTP configuration
4. **Stage Testing**: Test each stage transition to ensure proper workflow
5. **Notification Testing**: Verify that notifications are sent to correct groups and clients

## Monitoring and Debugging

The system now includes comprehensive logging. Check the application logs for:
- Email sending success/failure
- Stage transition details
- Group notification attempts
- Client upload URL generation

Look for log entries like:
```
INFO: Sending notifications for application APP2025-0001, action: application_complete, stage: Admin Fee Request
INFO: Found 3 groups for stage 3.0: ['TAO Group']
INFO: Successfully sent approval notification to group TAO Group
INFO: Successfully notified client
```

This will help you identify any remaining issues with the notification system.