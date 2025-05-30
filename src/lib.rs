use binaryninja::{
    architecture::CoreRegister,
    binary_view::BinaryViewExt as _,
    logger::Logger,
    low_level_il::{
        LowLevelILRegisterKind,
        expression::{ExpressionHandler, LowLevelILExpression, ValueExpr},
        function::{FunctionForm, FunctionMutability},
        instruction::{InstructionHandler, LowLevelILInstruction, LowLevelInstructionIndex},
        lifting::LowLevelILLabel,
    },
    rc::Ref,
    workflow::{Activity, AnalysisContext, Workflow},
};
use bn_bdash_extras::{activity, llil};

const ARM64E_PAC_ACTIVITY_NAME: &str = "bdash.arm64e-pac";

fn tag_type_for_view(
    view: &binaryninja::binary_view::BinaryView,
) -> Ref<binaryninja::tags::TagType> {
    view.tag_type_by_name("arm64e PAC")
        .unwrap_or_else(|| view.create_tag_type("arm64e PAC", "PAC"))
}

// Match `if ((<reg> & 0x40000000) == 0)`
// Returns `<reg>` and the operation coresponding to the `if`.
fn candidate_pac_check_register_from_if<'func, M, F>(
    instr: &'func LowLevelILInstruction<'func, M, F>,
) -> Option<(
    LowLevelILRegisterKind<CoreRegister>,
    LowLevelILInstruction<'func, M, F>,
)>
where
    M: FunctionMutability,
    F: FunctionForm,
    LowLevelILInstruction<'func, M, F>: InstructionHandler<'func, M, F>,
    LowLevelILExpression<'func, M, F, ValueExpr>: ExpressionHandler<'func, M, F>,
{
    use llil::{
        BinaryExpression,
        Expression::{And, CmpE, Const, Reg},
        Instruction::If,
    };

    let If(CmpE(cmp), true_target, ..) = instr.into() else {
        return None;
    };

    let BinaryExpression(And(and), Const(0)) = *cmp else {
        return None;
    };

    let BinaryExpression(Reg(reg), Const(0x4000_0000)) = *and else {
        return None;
    };

    Some((reg, true_target))
}

// Match `<reg_a> = <reg_b> ^ (<reg_b> << 1)`
fn is_explicit_pac_check<'func, M, F>(
    instr: &'func LowLevelILInstruction<'func, M, F>,
    register: LowLevelILRegisterKind<CoreRegister>,
) -> bool
where
    M: FunctionMutability + std::fmt::Debug,
    F: FunctionForm + std::fmt::Debug,
    LowLevelILInstruction<'func, M, F>: InstructionHandler<'func, M, F>,
    LowLevelILExpression<'func, M, F, ValueExpr>: ExpressionHandler<'func, M, F>,
{
    use llil::{
        BinaryExpression,
        Expression::{Const, Lsl, Reg, Xor},
        Instruction::SetReg,
    };

    let xor = match instr.into() {
        SetReg(dest, Xor(xor)) if dest == register => xor,
        _ => return false,
    };

    let BinaryExpression(Reg(left_reg), Lsl(lsl)) = *xor else {
        return false;
    };

    match *lsl {
        BinaryExpression(Reg(shifted_reg), Const(1)) => left_reg == shifted_reg,
        _ => false,
    }
}

fn process_arm64e_pac(analysis_context: &AnalysisContext) {
    let Some(llil) = (unsafe { analysis_context.llil_function() }) else {
        return;
    };

    let mut did_update = false;
    for idx in 0..=llil.instruction_count() {
        let Some(instr) = llil.instruction_from_index(LowLevelInstructionIndex(idx)) else {
            continue;
        };

        let Some((register, true_target)) = candidate_pac_check_register_from_if(&instr) else {
            continue;
        };
        let Some(prev) = llil.instruction_from_index(LowLevelInstructionIndex(instr.index.0 - 1))
        else {
            continue;
        };
        if !is_explicit_pac_check(&prev, register) {
            continue;
        }

        log::debug!(
            "Disabling explicit PAC check at {:#0x}-{:#0x}",
            prev.address(),
            instr.address()
        );

        if true_target.index == instr.index.next() {
            // Branch target is next instruction so we can replace the `if` with a `nop`.
            unsafe {
                llil.replace_expression(instr.expr_idx(), llil.nop());
            };
        } else {
            // Target is further afield so we replace the `if` with a `goto`.
            let mut label = llil
                .label_for_address(true_target.address())
                .unwrap_or_else(|| {
                    let mut label = LowLevelILLabel::new();
                    label.operand = true_target.index.0;
                    label
                });
            unsafe {
                llil.replace_expression(instr.expr_idx(), llil.goto(&mut label));
            };
        }

        // `xor` is always replaced with a `nop`.
        unsafe {
            llil.replace_expression(prev.expr_idx(), llil.nop());
        }
        did_update = true;

        analysis_context.function().add_tag(
            &tag_type_for_view(&analysis_context.view()),
            "Eliminated explicit pointer authentication check",
            Some(prev.address()),
            false,
            None,
        );
    }

    if did_update {
        llil.generate_ssa_form();
    }
}

fn register_activity(workflow: &Workflow) {
    if !workflow.registered() {
        log::debug!(
            "Skipping activity registration for workflow {} as it is not registered",
            workflow.name()
        );
        return;
    }

    let workflow = workflow.clone_to(&workflow.name());
    let config = activity::Config::action(
        ARM64E_PAC_ACTIVITY_NAME,
        "Remove explicit arm64e PAC checks",
        "Remove the explicit arm64e pointer authentication checks the compiler emits prior to tail calls",
    );
    let activity = Activity::new_with_action(&config.to_string(), process_arm64e_pac);
    workflow.register_activity(&activity).unwrap();
    workflow.insert(
        "core.function.generateMediumLevelIL",
        [ARM64E_PAC_ACTIVITY_NAME],
    );
    workflow.register().unwrap();
}

#[unsafe(no_mangle)]
pub extern "C" fn CorePluginDependencies() {
    use binaryninja::add_optional_plugin_dependency;
    add_optional_plugin_dependency("workflow_objc");
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginInit() -> bool {
    Logger::new("arm64 PAC")
        .with_level(log::LevelFilter::Debug)
        .init();

    register_activity(&Workflow::instance("core.function.metaAnalysis"));
    register_activity(&Workflow::instance("core.function.objectiveC"));

    true
}
